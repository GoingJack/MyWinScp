#pragma once
#pragma comment(lib,"./lib/libssh2.lib")
#pragma comment(lib, "ws2_32.lib")

#include "AllProtocol.h"
#include "./libheader/libssh2_config.h"
#include "./libheader/libssh2.h"



#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
# ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

#ifndef PASSWORDERROR
#define PASSWORDERROR	-1
#endif

#ifndef PUBLICKEYERROR
#define PUBLICKEYERROR	-2
#endif


class ScpProtocol : public AllProtocol
{
public:
	ScpProtocol();
	~ScpProtocol();
	void SetVal(CString &ipaddress, int &port, CString &username, CString &password);

	void setIpAddress(CString &ipaddress);
	void setUserName(CString &username);
	void setPassword(CString &password);
	void setScpPath(CString &scppath);
	void setPort(int &port);

	//��ʼ��ssh��������
	bool Initssh();

	//���Դ�Ҫ������ļ�
	bool OpenlocalFile();

	//�����׽ӿ�
	bool CreateSock();

	//��������Զ������
	bool Connect();

	//����session�Ự��ʵ��
	bool CreateSession();

	//�������ӣ���ӭ�����������Կ�����ü��ܣ�ѹ����MAC��
	bool StartupConnect();

	//��֤��� 
	int AuthenticateIdentity();

	//�ͷ���Դ
	void Release();
private:
	
	int sock, i, auth_pw;
	FILE *local;

	struct sockaddr_in sin;
	const char *fingerprint;
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;
	struct stat fileinfo;
	
	int rc;//����ֵ�������жϺ����Ƿ�ִ�гɹ�
	off_t got = 0;
};


