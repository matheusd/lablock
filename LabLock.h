/** LabLock **/

#define ESTADO_LIBERADO 	0
#define ESTADO_RESTRITO 	1
#define ESTADO_DESATIVADO 	2

#define NUM_LABS			1

//porta administrativa do lablock
#define ADMIN_PORT			15923
#define NETWORK				"10.10.13.0"
#define NETWORK_MASK		"255.255.255.0"
#define RULE_LIBERADO		59999

typedef struct info_lab {
	int lab_id;
	int estado;
	int ip_ini;
	int ip_fim;
} info_lab;

extern info_lab labs[1] = {

	{10, 0, 1, 30}

};
