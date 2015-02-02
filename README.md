Lablock - IPFW plugin for selective IP Blocking

This is an old project of mine, built (on my free time) while I worked at ETEC
Alcídio de Souza Prado.

This is meant to be a plugin for FreeBSD's IPFW. At the time, I used this 
(coupled with a web interface) for blocking or restricting particular IP ranges
(statically configured at each computer lab) from accessing the internet or
certain websites.

Lablock runs as a daemon and receives raw IP packets, decodes them, and checks
whether the source/destination IP is from a blocked or restricted lab. Depending
on the state of the lab, the packet is redirected to a given IPFW rule for
further processing.

At the time this worked great for our small lan, supporting over 140 
simultaneous users on an old AMD K6-II.

This is provided for historical and biographical purposes. It is provided as is,
and entirely unsupported.
