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
	recv_session = nullptr;
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

bool ScpProtocol::CreateSock(int &sockoption)
{
	
	sockoption = socket(AF_INET, SOCK_STREAM, 0);

	if (sockoption == -1)
		return false;
	return true;
}

bool ScpProtocol::Connect(int &sockoption)
{
	
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = hostaddr;

	if (connect(sockoption, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0)
		//failed to connect!\n
		return false;
	return true;
}

bool ScpProtocol::CreateSession(LIBSSH2_SESSION **sessionoption)
{
	*sessionoption = libssh2_session_init();
	if(!sessionoption)
		return false;
	return true;
}

bool ScpProtocol::StartupConnect(int &sockoption,LIBSSH2_SESSION *sessionoption)
{
	rc = libssh2_session_handshake(sessionoption, sockoption);
	if(rc)
		//Failure establishing SSH session: %d\n", rc
		return false;
	return true;
}

int ScpProtocol::AuthenticateIdentity(LIBSSH2_SESSION *sessionoption)
{
	fingerprint = libssh2_hostkey_hash(sessionoption, LIBSSH2_HOSTKEY_HASH_SHA1);
	if (auth_pw)
	{
		/* We could authenticate via password */
		if (libssh2_userauth_password(sessionoption, username, password))
		{
			return PASSWORDERROR;
		}
	}
	else
	{
		/* Or by public key */
		if (libssh2_userauth_publickey_fromfile(sessionoption, username,
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




int ScpProtocol::execOneCommand(const char *commandline,CString &result,int &sock_option,LIBSSH2_SESSION *session_option)
{
	/* Exec non-blocking on the remove host */
	LIBSSH2_CHANNEL *exec_channel;
	while ((exec_channel = libssh2_channel_open_session(session_option)) == NULL &&
		libssh2_session_last_error(session_option, NULL, NULL, 0) ==
		LIBSSH2_ERROR_EAGAIN)
	{
		waitsocket(sock_option, session_option);
	}
	if (exec_channel == NULL)
	{
		ReleaseExec(sock_option,session_option);
		return CHANNELERROR;	
	}
	while ((rc = libssh2_channel_exec(exec_channel, commandline)) ==
		LIBSSH2_ERROR_EAGAIN)
	{
		waitsocket(sock_option, session_option);
	}
	if (rc != 0)
	{
		ReleaseExec(sock_option, session_option);
		return EXECERROR;
	}
	for (;; )
	{
		/* loop until we block */
		int rc;
		do
		{
			char buffer[0x4000];
			rc = libssh2_channel_read(exec_channel, buffer, sizeof(buffer));
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
			waitsocket(sock_option, session);
		}
		else
			break;
	}
	libssh2_channel_close(exec_channel);
	return 0;
}

void ScpProtocol::ReleaseExec(int &sock_option,LIBSSH2_SESSION *session_option)
{
	int exitcode;
	char *exitsignal = (char *)"none";
	exitcode = 127;
	while ((rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN)
		waitsocket(sock_option, session_option);

	if (rc == 0)
	{
		exitcode = libssh2_channel_get_exit_status(channel);
		libssh2_channel_get_exit_signal(channel, &exitsignal,
			NULL, NULL, NULL, NULL, NULL);
	}

	if (exitsignal)
	{
		CString TEMP;
		TEMP.Format("\nGot signal: %s\n", exitsignal);
		//MessageBox(NULL, TEMP, "", MB_OK);
	}
	else
	{
		CString TEMP;
		TEMP.Format("\nEXIT: %d bytecount: %d\n", exitcode, bytecount);
		//MessageBox(NULL, TEMP, "", MB_OK);
	}
		

	libssh2_channel_free(channel);
	channel = NULL;
}

int ScpProtocol::SendFile(const CString & FilePath, const CString &ScpPath, CProgressCtrl &m_send_process)
{
	m_send_process.ShowWindow(SW_NORMAL);


	if (OpenlocalFile(FilePath))
	{
		return OPENFILEERROR;
	}
	channel = libssh2_scp_send(session,ScpPath,fileinfo.st_mode & 0777, 
		(unsigned long)fileinfo.st_size);
	if (!channel)
	{
		int timeout = 0;
		libssh2_channel_free(channel);
		channel = NULL;
		while (!(channel = libssh2_scp_send(session, ScpPath, fileinfo.st_mode & 0777,
			(unsigned long)fileinfo.st_size)))
		{
			if (timeout == 10)
				break;
			timeout++;
		}

		return CANNOTOPENS;
	}
	size_t nread;
	char mem[1024 *24];
	char *ptr;
	bool flag =false;

	long  totalsize = fileinfo.st_size; 
	int current = 0;


	do {
		nread = fread(mem, 1, 1024 * 24, local);
		//更新进度条/
		current += (1024 * 24);
		double ff = (double)current / (double)totalsize;
		int current_precent = int(ff * 100);
		

		m_send_process.SetPos(current_precent);


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
		fclose(local);
	}
	fclose(local);
	return 0;
}

void ScpProtocol::channel_shell_init(CString &init)
{
	channel_shell = libssh2_channel_open_session(session);
	if (channel_shell == NULL)
	{
		MessageBox(NULL,"init channel_shell failed!\n","提示",MB_OK);
		return;
	}
	if (libssh2_channel_request_pty(channel_shell, "xterm") != 0) {
		MessageBox(NULL, "Failed to request a pty\n", "提示", MB_OK);
		return;
	}
	if (libssh2_channel_shell(channel_shell) != 0) {
		MessageBox(NULL, "Failed to open a shell", "提示", MB_OK);
		return;
	}
	char initbuf[1024] = { 0 };
	libssh2_channel_read(channel_shell, initbuf, 1024);
	init = initbuf;
}

void ScpProtocol::channel_shell_exec(const CString command,CString &result)
{
	char sendbuf[2048] = { 0 };
	char recvbuf[2048] = { 0 };
	sprintf(sendbuf, "%s\n", command);
	libssh2_channel_write(channel_shell, sendbuf, strlen(sendbuf));

	libssh2_channel_read(channel_shell, recvbuf, 2048);
	result = recvbuf;
}

void ScpProtocol::channel_shell_free()
{
	libssh2_channel_free(channel_shell);
	channel_shell = NULL;
}

bool ScpProtocol::recv_file_vid_scp(CString scppath,CString destination, CProgressCtrl &m_recv_process)
{
	m_recv_process.SetPos(0);
	m_recv_process.ShowWindow(SW_NORMAL);
	int total = 0;
	FILE *fp = fopen(destination, "wb");
	if (fp == NULL)
	{
		MessageBox(NULL, "选择位置没有写入权限", "警告", NULL);
		return FALSE;
	}
	stat(destination, &recv_fileinfo);
	long filesize;
	long currentsize = 0;
	do 
	{
		recv_channel = libssh2_scp_recv(recv_session, scppath, &recv_fileinfo);
		filesize = recv_fileinfo.st_size;
		if (!recv_channel) {
			if (libssh2_session_last_errno(recv_session) != LIBSSH2_ERROR_EAGAIN) {
				char *err_msg;

				libssh2_session_last_error(recv_session, &err_msg, NULL, 0);
				//fprintf(stderr, "%s\n", err_msg);
				return FALSE;
			}
			else {
				//fprintf(stderr, "libssh2_scp_recv() spin\n");
				waitsocket(sock, recv_session);
			}
		}
	} while (!recv_channel);
	//fprintf(stderr, "libssh2_scp_recv() is done, now receive data!\n");
	while (got < recv_fileinfo.st_size) {
		char mem[1024 * 24];
		int rc;

		do {
			int amount = sizeof(mem);

			if ((recv_fileinfo.st_size - got) < amount) {
				amount = recv_fileinfo.st_size - got;
			}
			if (amount == 0)
				break;
			/* loop until we block */
			rc = libssh2_channel_read(recv_channel, mem, amount);
			currentsize += rc;
			int current_precent = ((double)currentsize / (double)filesize) * 100;
			m_recv_process.SetPos(current_precent);
			if (rc > 0) {
				//write(1, mem, rc);
				//mem[rc] = '\0';
				fwrite(mem, sizeof(char), rc, fp);
				//fprintf(fp,"%s", mem);
				got += rc;
				total += rc;
			}
		} while (rc > 0);
	}
	got = 0;
	fclose(fp);
	return TRUE;

}

void ScpProtocol::recv_release()
{
	if (recv_session)
	{
		libssh2_session_free(recv_session);
	}
	if (recv_sock != -1)
	{
		closesocket(recv_sock);
	}
}

void ScpProtocol::Release(int &sockoption,LIBSSH2_SESSION *sessionoption)
{
	if (sessionoption)
	{
		libssh2_session_free(sessionoption);
	}
	if (sockoption != -1)
	{
		closesocket(sockoption);
	}
	if (local)
	{
		fclose(local);
		local = nullptr;
	}
}


