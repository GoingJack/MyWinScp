#include "stdafx.h"
#include "ScpProtocol.h"



ScpProtocol::ScpProtocol()
{
	//注册使用套接口函数
	WSADATA wsadata;

	WSAStartup(MAKEWORD(2, 0), &wsadata);
	auth_pw = 1;
	local = 0;
	session = nullptr;
	sock = -1;
}


ScpProtocol::~ScpProtocol()
{
	
}

void ScpProtocol::SetVal(CString & ipaddress, int &port, CString & username, CString & password)
{
	

	setIpAddress(ipaddress);
	setPort(port);
	setUserName(username);
	setPassword(password);
	
}

void ScpProtocol::setIpAddress(CString &ipaddress)
{
	this->hostaddr = inet_addr(ipaddress);
}

void ScpProtocol::setUserName(CString &username)
{
	this->username = username;
}

void ScpProtocol::setPassword(CString &password)
{
	this->password = password;
}

void ScpProtocol::setScpPath(CString & scppath)
{
	this->remotepath = scppath;
}

void ScpProtocol::setPort(int & port)
{
	this->port = port;
}

bool ScpProtocol::Initssh()
{
	rc = libssh2_init(0);
	if (rc != 0)
		//libssh2 initialization failed (%d)\n", rc)
		return false;
	return true;
}

int ScpProtocol::OpenlocalFile(const CString &FilePath)
{
	local = fopen(FilePath, "rb");
	if (local == nullptr)
		return OPENFILEERROR;
	stat(FilePath, &fileinfo);
	return 0;
}

bool ScpProtocol::CreateSock()
{
	
	sock = socket(AF_INET, SOCK_STREAM, 0);

	if (sock == -1)
		return false;
	return true;
}

bool ScpProtocol::Connect()
{
	
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = hostaddr;

	if (connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0)
		//failed to connect!\n
		return false;
	return true;
}

bool ScpProtocol::CreateSession()
{
	session = libssh2_session_init();
	if(!session)
		return false;
	return true;
}

bool ScpProtocol::StartupConnect()
{
	rc = libssh2_session_handshake(session, sock);
	if(rc)
		//Failure establishing SSH session: %d\n", rc
		return false;
	return true;
}

int ScpProtocol::AuthenticateIdentity()
{
	fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
	if (auth_pw)
	{
		/* We could authenticate via password */
		if (libssh2_userauth_password(session, username, password))
		{
			return PASSWORDERROR;
		}
	}
	else
	{
		/* Or by public key */
		if (libssh2_userauth_publickey_fromfile(session, username,
			"/home/username/.ssh/id_rsa.pub",
			"/home/username/.ssh/id_rsa",
			password)) {
			return PUBLICKEYERROR;
		}
	}
	return 0;
}

int ScpProtocol::SendFile(const CString & FilePath, const CString &ScpPath)
{
	if (OpenlocalFile(FilePath))
	{
		return OPENFILEERROR;
	}
	channel = libssh2_scp_send(session,ScpPath,fileinfo.st_mode & 0777, 
		(unsigned long)fileinfo.st_size);
	if (!channel)
	{
		return CANNOTOPENS;
	}
	size_t nread;
	char mem[1024];
	char *ptr;
	bool flag =false;
	do {
		nread = fread(mem, 1, sizeof(mem), local);
		if (nread <= 0) {
			/* end of file */
			break;
		}
		ptr = mem;

		do {
			/* write the same data over and over, until error or completion */
			rc = libssh2_channel_write(channel, ptr, nread);
			if (rc < 0) {
				flag = true;
				break;
			}
			else {
				/* rc indicates how many bytes were written this time */
				ptr += rc;
				nread -= rc;
			}
		} while (nread);

	} while (1);
	libssh2_channel_send_eof(channel);
	libssh2_channel_wait_eof(channel);
	libssh2_channel_wait_closed(channel);
	//libssh2_session_free(channel);
	channel = nullptr;
	if (flag == true)
	{
		return SENDERROR;
	}
	return 0;
}

void ScpProtocol::Release()
{
	if (session)
	{
		libssh2_session_free(session);
	}
	if (sock != -1)
	{
		closesocket(sock);
	}
	if (local)
	{
		fclose(local);
		local = nullptr;
	}
}
