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
	this->hostaddr = inet_addr(ipaddress);//转化为网络字节序
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

int ScpProtocol::waitsocket(int socket_fd, LIBSSH2_SESSION * session)
{
	struct timeval timeout;
	int rc;
	fd_set fd;
	fd_set *writefd = NULL;
	fd_set *readfd = NULL;
	int dir;

	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	FD_ZERO(&fd);

	FD_SET(socket_fd, &fd);

	/* now make sure we wait in the correct direction */
	dir = libssh2_session_block_directions(session);

	if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
		readfd = &fd;

	if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
		writefd = &fd;

	rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);

	return rc;
}




int ScpProtocol::execOneCommand(const char *commandline,CString &result)
{
	/* Exec non-blocking on the remove host */
	while ((channel = libssh2_channel_open_session(session)) == NULL &&
		libssh2_session_last_error(session, NULL, NULL, 0) ==
		LIBSSH2_ERROR_EAGAIN)
	{
		waitsocket(sock, session);
	}
	if (channel == NULL)
	{
		ReleaseExec();
		return CHANNELERROR;	
	}
	while ((rc = libssh2_channel_exec(channel, commandline)) ==
		LIBSSH2_ERROR_EAGAIN)
	{
		waitsocket(sock, session);
	}
	if (rc != 0)
	{
		ReleaseExec();
		return EXECERROR;
	}
	for (;; )
	{
		/* loop until we block */
		int rc;
		do
		{
			char buffer[0x4000];
			rc = libssh2_channel_read(channel, buffer, sizeof(buffer));
			if (rc > 0)
			{
				buffer[rc] = '\0';
				result = buffer;
				return 0;
				/*int i;
				bytecount += rc;
				fprintf(stderr, "We read:\n");
				for (i = 0; i < rc; ++i)
					fputc(buffer[i], stderr);
				fprintf(stderr, "\n");*/
			}
			else {
				if (rc != LIBSSH2_ERROR_EAGAIN)
					return ERRORCOMMAND;
					/* no need to output this for the EAGAIN case */
					//fprintf(stderr, "libssh2_channel_read returned %d\n", rc);
			}
		} while (rc > 0);

		/* this is due to blocking that would occur otherwise so we loop on
		   this condition */
		if (rc == LIBSSH2_ERROR_EAGAIN)
		{
			waitsocket(sock, session);
		}
		else
			break;
	}
	return 0;
}

void ScpProtocol::ReleaseExec()
{
	int exitcode;
	char *exitsignal = (char *)"none";
	exitcode = 127;
	while ((rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN)
		waitsocket(sock, session);

	if (rc == 0)
	{
		exitcode = libssh2_channel_get_exit_status(channel);
		libssh2_channel_get_exit_signal(channel, &exitsignal,
			NULL, NULL, NULL, NULL, NULL);
	}

	if (exitsignal)
		printf("\nGot signal: %s\n", exitsignal);
	else
		printf("\nEXIT: %d bytecount: %d\n", exitcode, bytecount);

	libssh2_channel_free(channel);
	channel = NULL;
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
