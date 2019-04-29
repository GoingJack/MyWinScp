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

	//初始化ssh连接请求
	bool Initssh();

	//尝试打开要传输的文件
	bool OpenlocalFile();

	//创建套接口
	bool CreateSock();

	//尝试连接远程主机
	bool Connect();

	//创建session会话的实例
	bool CreateSession();

	//启动连接，欢迎横幅，交换密钥，设置加密，压缩和MAC层
	bool StartupConnect();

	//认证身份 
	int AuthenticateIdentity();

	//释放资源
	void Release();
private:
	
	int sock, i, auth_pw;
	FILE *local;

	struct sockaddr_in sin;
	const char *fingerprint;
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;
	struct stat fileinfo;
	
	int rc;//返回值，用于判断函数是否执行成功
	off_t got = 0;
};


