/* LabLock

Bloqueador de laboratórios da ETE Alcídio.
(C) 2007 Matheus Degiovani

Usado em conjunto com ipfw e divert em ambientes FreeBSD para
bloqueio dinâmico de laboratórios.

*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pwd.h>
#include <string.h>
#include "LabLock.h"

#define LABLOCK_PORT 		4522
#define INADDR_ANY      	(u_int32_t)0x00000000

#define MAXHOSTNAME			128
#define RECV_BUFFER_SIZE 	8192

//lista de portas bloqueadas
int * blocked_ports;
int numBlockedPorts;

int findLabState(int lastDec) {
	int i;
	for (i = 0; i < NUM_LABS; i++) {
		if (lastDec >= labs[i].ip_ini && lastDec <= labs[i].ip_fim) {
			//esse comp faz parte desse lab. Retornar o estado desse lab
			return labs[i].estado;
		}
	}
	return -1;
}

int findLabById(int id) {
	int i;
	for (i = 0; i < NUM_LABS; i++) {
		if (labs[i].lab_id == id) {
			//achou o lab. Retornar seu índice.
			return i;
		}
	}
	return -1;
}

void readConfFiles(char *prefix) {
	FILE *arq;
	char line[256];
	int *port;
	char *filename;

	filename = (char *)calloc(strlen(prefix) + strlen("blocked_ports") + 1,
                        sizeof(char));
	strcat(filename, prefix);
	strcat(filename, "blocked_ports");

	if ((arq = fopen(filename, "r")) == NULL)
		fprintf(stderr, "Cannot open %s\n", filename);
	else {
		blocked_ports = malloc(0);
		numBlockedPorts = 0;
		while (fgets((char *) &line, 255, arq) != NULL) {
			if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') continue;

			blocked_ports = (int *)realloc(blocked_ports, numBlockedPorts+1);
			port = blocked_ports + numBlockedPorts;
			*port = strtol(&line, NULL, 0);
			numBlockedPorts++;

			//fprintf(stdout, "blocking port %d\n", *port);
		}
		fclose(arq);
	}

	free(filename);
}

int packetBlocked(int labState, int srcPort, int dstPort, struct sockaddr_in *from) {

	int *port = blocked_ports;	
	int i;

	if (labState == ESTADO_LIBERADO) {
		//mudar endereço para pular regras de bloqueio do firewall
		fprintf(stdout, "mudando para %d\n", RULE_LIBERADO);
		from->sin_port = RULE_LIBERADO;
		return 0;	
	} else if (labState == ESTADO_DESATIVADO)
		return 1;
				
	//estado restrito. Checar portas
	for (i = 0; i < numBlockedPorts; i++) {
		if (srcPort == *port || dstPort == *port) {
			//bloqueado
			return 1;
		}
		port++;
	}

	//se chegou até aqui, não está bloqueando
	return 0;
}

void processAdminPkt(char *recvbuff, int len, struct ip *ipHeader, int ipHeadLen) {
	struct tcphdr *tcpHeader;
	//struct udphdr *udpHeader;
	char *data;	
	int acao, lab;
	int labid;
	
	if (ipHeader->ip_p == IPPROTO_TCP) {		
		bcopy(recvbuff + ipHeadLen, tcpHeader, sizeof(tcpHeader));
		data = recvbuff + ipHeadLen + tcpHeader->th_off * 4;
	} else if (ipHeader->ip_p == IPPROTO_UDP) {		
		//bcopy(recvbuff + ipHeadLen, udpHeader, sizeof(udpHeader));		
		data = recvbuff + ipHeadLen + 8;
	}	
	acao = data[0];
	
	//se for ação de atualização de conf.
	if (acao == 'U') {
		readConfFiles("./");
		return;
	}
	
	labid = data[1];
	lab = findLabById(labid);
	//fprintf(stdout, "Processando pacote administrativo %d em lab %d (%d)\n", acao, labid, lab);
	
	if (lab > -1) {
		switch (acao) {
			case 'L': labs[lab].estado = ESTADO_LIBERADO; break;
			case 'R': labs[lab].estado = ESTADO_RESTRITO; break;
			case 'D': labs[lab].estado = ESTADO_DESATIVADO; break;
		}
		labid = labs[lab].lab_id;
		//fprintf(stdout, "Novo estado do %d lab %d e %d\n", labid, lab, labs[lab].estado);
	}
}

void processPacket(char *recvbuff, int len, struct sockaddr_in *from,
				   int fromlen, int socket)
{
	struct ip *header;
	int headlen;
	struct in_addr src_add, dst_add, sel_add;
	int lastDec;
	int ports;
	int state;
	int blocked;
	int srcMatches, dstMatches;
	uint16_t srcPort, dstPort;

	//medir cabeçalho
	headlen = ((int) *recvbuff) & 0xf0 >> 4; //in 32 bit octets

	//pegar cabeçalho
	header = malloc(headlen*4);
	bcopy(recvbuff, header, headlen*4);
	src_add = header->ip_src;
	dst_add = header->ip_dst;

	//decodificar cabeçalho TCP/UDP
	switch (header->ip_p) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			bcopy(recvbuff + headlen*4, &ports, 4);
			dstPort = ntohs((ports & 0xffff0000) >> 16);
			srcPort = ntohs(ports & 0xffff);
			break;
		default:
			srcPort = 0;
			dstPort = 0;
	}
	
	//testar se é um pacote administrador
	if (dstPort == ADMIN_PORT) {
		processAdminPkt(recvbuff, len, header, headlen*4);
		return;
	}	

	//verificar se src ou dst do pacote é da rede sendo controlada
	//pelo labLock
	srcMatches = (src_add.s_addr & inet_addr(NETWORK_MASK)) == inet_addr(NETWORK);
	dstMatches = (dst_add.s_addr & inet_addr(NETWORK_MASK)) == inet_addr(NETWORK);
	//fprintf(stdout, "matches: %d %d\n", srcMatches, dstMatches);
	if (srcMatches) {
		sel_add = src_add;
		//fprintf(stdout, "selecionando pelo src_add\n");
	} else if (dstMatches) {
		sel_add = dst_add;
		//fprintf(stdout, "selecionando pelo dst_add\n");
	} else {
		//roteando pacote que não pertence à rede controlada pelo lablock
		//simplesmente permitir passagem
		//fprintf(stdout, "roteando pacotes nao controlados pelo lablock %s, %s\n", 
			//	inet_ntoa(src_add.s_addr & inet_addr(NETWORK_MASK)), 
				//inet_ntoa(dst_add.s_addr & inet_addr(NETWORK_MASK)));
		//fprintf(stdout, "roteando pacotes nao controlados pelo lablock %d, %d mask %d\n", 
		//		src_add.s_addr & inet_addr(NETWORK_MASK), 
		//		dst_add.s_addr & inet_addr(NETWORK_MASK), 
		//		inet_addr(NETWORK));		
		sendto(socket, recvbuff, len, 0, (struct sockaddr *) from, fromlen);
		return;
	}	
	
	//descobrir último digito do ip
	lastDec = (sel_add.s_addr & 0xff000000) >> 24;
	
	//fprintf(stdout,"reding from %#x src: %d  dst: %d\n",ports, srcPort, dstPort);
	state = findLabState(lastDec);
	//fprintf(stdout, "lab state eh %d\n", state);
	blocked = packetBlocked(state, srcPort, dstPort, from);
	if (blocked) {
		//se esse comp/lab está bloqueado dropar pacote
		//talvez fosse melhor mandar um ICMP 3 (host unreachable) mas só
		//dropando o aluno vai precisar esperar um timeout pra saber q
		//a mensagem não chegou, o que é sempre divertido... :)
		
		//fprintf(stdout,"bloqueando src: %d  dst: %d\n",srcPort, dstPort);
	} else {
		//senão, deixar passar para as próximas regras do IPFW				
		//fprintf(stdout, "enviando para %d\n", from->sin_port);
		sendto(socket, recvbuff, len, 0, (struct sockaddr *) from, fromlen);
		//fprintf(stdout,"allowed src: %d  dst: %d\n",srcPort, dstPort);
	}
}

int isArgSet(int argc, char **argv, char *arg) {
	int i;
	for (i = 1; i < argc; i++) {
		if (!strcmp(arg, argv[i]))
			return 1;
	}
	return 0;
}

int main(int argc, char **argv) {
	int s,t;
	int i, fromlen;
	struct sockaddr_in sa, from;
	struct hostent *hp;
	char *myname;
	struct servent *sp;
	char localhost[MAXHOSTNAME+1];
    char *protocol;
	unsigned short port;
	char recvbuff[RECV_BUFFER_SIZE];
	int len;
		
	if (isArgSet(argc, argv, "-h")) {
		fprintf(stdout, "LabLock - Controle de laboratorios da ETE Alcicio\n");
		fprintf(stdout, "(C) 2007 by Matheus Degiovani\n\n");
		fprintf(stdout, "Usage: LabLock [-h][-D]\n");
		fprintf(stdout, "    -h: Mensagem de ajuda\n");
		fprintf(stdout, "    -D: Nao iniciar como daemon\n");
		return 0;
	}
	
	readConfFiles("./");
	
	if (!isArgSet(argc, argv, "-D"))
		daemon(0, 0);	

	myname  = argv[0];
	protocol="tcp";
	port = LABLOCK_PORT;

	bzero(&sa, sizeof sa);
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	sa.sin_family = AF_INET;

	if((s=socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT)) <0) {
		perror("socket()");
		exit(1);
	}

	if(bind(s, (struct sockaddr*) &sa,sizeof(sa)) < 0) {
		perror("bind()");
		exit(1);
	}
	//fprintf(stdout, "listening\n");
	for(;;) {
		len = recvfrom(s, &recvbuff, sizeof(recvbuff), MSG_WAITALL,
					   (struct sockaddr*) &from, &fromlen);
		processPacket((char *)&recvbuff, len, &from, fromlen, s);
		//fprintf(stdout,"%s: listening service read %d bytes\n",myname,len);
	}
}




