
// WinSCPView.cpp: CWinSCPView 类的实现
//

#include "stdafx.h"
// SHARED_HANDLERS 可以在实现预览、缩略图和搜索筛选器句柄的
// ATL 项目中进行定义，并允许与该项目共享文档代码。
#ifndef SHARED_HANDLERS
#include "WinSCP.h"
#endif

#include "WinSCPDoc.h"
#include "WinSCPView.h"
#include "CLoginDIalog.h"

extern ScpProtocol sc;
struct lp {
	CWinSCPView *m_p;
	char *selectPath;

	char *remote_file;
};

DWORD _stdcall Thread_Begin_Send(LPVOID lparam)
{
	lp *m_this = (lp*)malloc(sizeof(lp));
	m_this = (lp*)lparam;
	m_this->m_p->My_SendFile(m_this->selectPath);

	m_this->m_p->GetDlgItem(IDC_BUTTON1)->EnableWindow(TRUE);
	m_this->m_p->m_send_process.ShowWindow(SW_HIDE);
	return 0;
}

DWORD _stdcall Thread_Begin_Download(LPVOID lparam)
{
	lp *m_this = (lp*)malloc(sizeof(lp));
	m_this = (lp*)lparam;
	m_this->m_p->DownloadFile(m_this->selectPath);

	m_this->m_p->GetDlgItem(IDC_BUTTON6)->EnableWindow(TRUE);
	m_this->m_p->m_recv_process.ShowWindow(SW_HIDE);

	return 0;
}




#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CWinSCPView

IMPLEMENT_DYNCREATE(CWinSCPView, CFormView)

BEGIN_MESSAGE_MAP(CWinSCPView, CFormView)
	// 标准打印命令
	ON_COMMAND(ID_FILE_PRINT, &CFormView::OnFilePrint)
	ON_COMMAND(ID_FILE_PRINT_DIRECT, &CFormView::OnFilePrint)
	ON_COMMAND(ID_FILE_PRINT_PREVIEW, &CFormView::OnFilePrintPreview)
	ON_BN_CLICKED(IDC_BUTTON1, &CWinSCPView::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON3, &CWinSCPView::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON4, &CWinSCPView::OnBnClickedButton4)
	ON_BN_CLICKED(IDC_BUTTON5, &CWinSCPView::OnBnClickedButton5)
	ON_BN_CLICKED(IDC_BUTTON6, &CWinSCPView::OnBnClickedButton6)
	ON_WM_CLOSE()
	ON_BN_CLICKED(IDC_BUTTON7, &CWinSCPView::OnBnClickedButton7)
END_MESSAGE_MAP()

// CWinSCPView 构造/析构

CWinSCPView::CWinSCPView()  noexcept
	: CFormView(IDD_WINSCP_FORM)
	, m_remote_file(_T("/tmp/TEST"))
	, mv_remotePath(_T("/tmp/"))
	, m_commandline("")

{
	// TODO: 在此处添加构造代码

}

CWinSCPView::~CWinSCPView()
{
}

void CWinSCPView::DoDataExchange(CDataExchange* pDX)
{
	CFormView::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT1, mv_remotePath);
	DDX_Text(pDX, IDC_EDIT4, m_commandline);
	DDX_Control(pDX, IDC_RICHEDIT21, m_richedit1);
	DDX_Control(pDX, IDC_PROGRESS1, m_send_process);
	DDX_Control(pDX, IDC_PROGRESS2, m_recv_process);
	//  DDX_Control(pDX, IDC_MFCEDITBROWSE3, m_recv_path);
	DDX_Text(pDX, IDC_EDIT6, m_remote_file);
}

BOOL CWinSCPView::PreCreateWindow(CREATESTRUCT& cs)
{
	// TODO: 在此处通过修改
	//  CREATESTRUCT cs 来修改窗口类或样式

	return CFormView::PreCreateWindow(cs);
}

void CWinSCPView::OnInitialUpdate()
{
	CFormView::OnInitialUpdate();
	GetParentFrame()->RecalcLayout();
	ResizeParentToFit();

	//我的初始化
	
	//UpdateData(TRUE);
	CenterWindow();

	GetDlgItem(IDC_BUTTON4)->EnableWindow(FALSE);
	

	//进度条
	m_send_process.SetRange(0, 100);
	m_send_process.SetPos(0);
	m_send_process.ShowWindow(SW_HIDE);

	m_recv_process.SetRange(0, 100);
	m_recv_process.SetPos(0);
	m_recv_process.ShowWindow(SW_HIDE);

	//设置目前不用的控件不显示
	GetDlgItem(IDC_EDIT4)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_EDIT5)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_RICHEDIT21)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_BUTTON3)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_BUTTON4)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_BUTTON5)->ShowWindow(SW_HIDE);

}


// CWinSCPView 打印

BOOL CWinSCPView::OnPreparePrinting(CPrintInfo* pInfo)
{
	// 默认准备
	return DoPreparePrinting(pInfo);
}

void CWinSCPView::OnBeginPrinting(CDC* /*pDC*/, CPrintInfo* /*pInfo*/)
{
	// TODO: 添加额外的打印前进行的初始化过程
}

void CWinSCPView::OnEndPrinting(CDC* /*pDC*/, CPrintInfo* /*pInfo*/)
{
	// TODO: 添加打印后进行的清理过程
}

void CWinSCPView::OnPrint(CDC* pDC, CPrintInfo* /*pInfo*/)
{
	// TODO: 在此处添加自定义打印代码
}


// CWinSCPView 诊断

#ifdef _DEBUG
void CWinSCPView::AssertValid() const
{
	CFormView::AssertValid();
}

void CWinSCPView::Dump(CDumpContext& dc) const
{
	CFormView::Dump(dc);
}

CWinSCPDoc* CWinSCPView::GetDocument() const // 非调试版本是内联的
{
	ASSERT(m_pDocument->IsKindOf(RUNTIME_CLASS(CWinSCPDoc)));
	return (CWinSCPDoc*)m_pDocument;
}
#endif //_DEBUG


// CWinSCPView 消息处理程序

//发送文件按钮
void CWinSCPView::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	GetDlgItem(IDC_BUTTON1)->EnableWindow(FALSE);

	UpdateData(TRUE);
	CString selectPath;
	GetDlgItemText(IDC_MFCEDITBROWSE1, selectPath);
	if (!PathFileExists(selectPath))
	{
		MessageBox("文件不存在!\n");
	}

	//判断远程目录是否存在
	if (!isRemotePathexist(mv_remotePath,0,sc.sock,sc.session))
	{
		//MessageBox("远程目录不存在");
		//OnBnClickedButton7();
		RefreshSession(sc.sock, sc.session);
		if (MessageBox("发送失败\n重新发送", "", MB_YESNO) == IDYES)
		{
			OnBnClickedButton1();
		}
		else
		{
			GetDlgItem(IDC_BUTTON1)->EnableWindow(TRUE);
		}
		return;
	}

	//发送文件
	//My_SendFile(selectPath);
	//线程
	lp* sf = (lp*)malloc(sizeof(lp));
	sf->m_p = this;
	
	sf->selectPath = (char *)malloc(selectPath.GetLength() + 1);
	memset(sf->selectPath, 0, selectPath.GetLength() + 1);
	char *tmp = NULL;
	CStringA TMP_selectPath = selectPath;
	tmp = TMP_selectPath.GetBuffer();
	strcpy(sf->selectPath, tmp);
	CreateThread(NULL, 0, Thread_Begin_Send,
		(LPVOID)sf, NULL, NULL);

	/*CWinThread* AFXAPI AfxBeginThread(AFX_THREADPROC pfnThreadProc, LPVOID pParam,
		int nPriority = THREAD_PRIORITY_NORMAL, UINT nStackSize = 0,
		DWORD dwCreateFlags = 0, LPSECURITY_ATTRIBUTES lpSecurityAttrs = NULL);*/
	
}

CString CWinSCPView::SpliteFileName(const CString & selectfilepath)
{
	CFile spliter;
	spliter.SetFilePath(selectfilepath);

	return spliter.GetFileName();
}

//可以判断命令是否执行成功的执行命令，二次封装函数
BOOL CWinSCPView::execACommand(const char * commandline,CString &ShowResult)
{
	if (nullptr == commandline)return false;
	char commandCatReturn[128] = { 0 };
	sprintf(commandCatReturn, "%s;echo $?", commandline);
CString result;
//int res = sc.execOneCommand(commandCatReturn, result);
int res;
ShowResult = result;
if (res == 0)
{
	CString LastResult = result.Right(2);
	if (strcmp(LastResult.Left(1), "0") == 0)//如果结果最后一个字符为0代表命令执行成功，否则执行失败
	{
		return true;
	}
	else
	{
		return false;
	}
}
return false;
}

BOOL CWinSCPView::isRemotePathexist(CString Apath,int mode,int sock_option,LIBSSH2_SESSION * session_option)
{
	char isexist[128] = { 0 };
	sprintf(isexist, "ls %s", Apath);
	CString exec_result;
	int resfromexec = sc.execOneCommand(isexist, exec_result, sock_option, session_option);
	if (resfromexec == CHANNELERROR)
	{
		//MessageBox("channel error!\n");
		return false;
	}
	else if (resfromexec == EXECERROR)
	{
		//MessageBox("exec fun error!\n");
		return false;
	}
	else if (resfromexec == ERRORCOMMAND)
	{
		if (mode == 1)
		{
			MessageBox("要下载的文件不存在!\n");
			return false;
		}
		if (MessageBox("remote path is not exist,command exec output is stderr!\n would you like to create it?", "warnning!!!", MB_YESNO) == IDYES)
		{
			char MDcommand[128] = { 0 };
			sprintf(MDcommand, "mkdir -p %s", Apath);
			CString result;
			if (execACommand(MDcommand, result))//创建成功目录后返回结果为0，故不能通过有没有返回内容来判断是否成功创建
			{
				MessageBox("创建成功!\n");
				return true;
			}
		}
		return false;
	}
	else return true;
}

bool CWinSCPView::My_SendFile(CString selectPath)
{
	if (mv_remotePath.Right(1) != "/")
		mv_remotePath += "/";
	CString remotePathCatFilename = mv_remotePath + SpliteFileName(selectPath);
	int rs = sc.SendFile(selectPath, remotePathCatFilename ,m_send_process);
	if (rs == OPENFILEERROR)
	{
		char localfileerror[1024];
		sprintf(localfileerror, "打开 %s 文件失败\n", selectPath);
		MessageBox(localfileerror);
		m_send_process.ShowWindow(SW_HIDE);
		GetDlgItem(IDC_BUTTON1)->EnableWindow(TRUE);
		return false;
	}
	else if (rs == CANNOTOPENS)
	{
		MessageBox("打开session失败\n");
		RefreshSession(sc.sock, sc.session);
		My_SendFile(selectPath);
		return false;
	}
	else if (rs == SENDERROR)
	{
		MessageBox("发送失败\n");
		m_send_process.ShowWindow(SW_HIDE);
		GetDlgItem(IDC_BUTTON1)->EnableWindow(TRUE);
		return false;
	}
	else if (rs == 0)
	{
		MessageBox("传送成功!\n");
		m_send_process.SetPos(0);
		return true;
	}
}

//执行命令

void CWinSCPView::ExecAndShow()
{
	UpdateData(TRUE);
	CString result;
	sc.channel_shell_exec(m_commandline, result);
	CString lastresult;
	GetDlgItemText(IDC_EDIT5, lastresult);
	lastresult += result;
	SetDlgItemText(IDC_EDIT5, lastresult);
}




BOOL CWinSCPView::PreTranslateMessage(MSG* pMsg)
{
	// TODO: 在此添加专用代码和/或调用基类
	if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_RETURN)
	{
		if (GetFocus()->GetDlgCtrlID() == IDC_EDIT4)
		{
			ExecAndShow();
		}
	}

	return CFormView::PreTranslateMessage(pMsg);
}

//shell连接
void CWinSCPView::OnBnClickedButton3()
{
	// TODO: 在此添加控件通知处理程序代码
	CString result;
	sc.channel_shell_init(result);
	SetDlgItemText(IDC_EDIT5, result);
	
	GetDlgItem(IDC_BUTTON4)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON3)->EnableWindow(FALSE);
}

//shell断开连接
void CWinSCPView::OnBnClickedButton4()
{
	// TODO: 在此添加控件通知处理程序代码
	if (sc.channel_shell != NULL)
	{
		sc.channel_shell_free();
		SetDlgItemText(IDC_EDIT5, "断开成功！\n");
		GetDlgItem(IDC_BUTTON3)->EnableWindow(TRUE);
		GetDlgItem(IDC_BUTTON4)->EnableWindow(FALSE);
	}

}


void CWinSCPView::OnBnClickedButton5()
{
	 //TODO: 在此添加控件通知处理程序代码
	CHARFORMAT cf, cf_2; //定义若干字体
	ZeroMemory(&cf, sizeof(CHARFORMAT));
	cf.cbSize = sizeof(CHARFORMAT);
	cf.dwMask = CFM_BOLD | CFM_COLOR | CFM_FACE | CFM_ITALIC | CFM_SIZE | CFM_UNDERLINE;
	cf.dwEffects = 0;
	cf.yHeight = 15 * 15; //文字高度
	cf.crTextColor = RGB(0, 255, 0); //文字颜色黑色000，白色全255
	strcpy(cf.szFaceName, _T("宋体")); //设置字体

	m_richedit1.SetSel(-1, -1);
	m_richedit1.SetSelectionCharFormat(cf);
	char str[123] = { "你好颜色绿色" };
	m_richedit1.ReplaceSel(str);
}


//下载文件
void CWinSCPView::OnBnClickedButton6()
{
	// TODO: 在此添加控件通知处理程序代码
	GetDlgItem(IDC_BUTTON6)->EnableWindow(FALSE);
	m_recv_process.ShowWindow(SW_NORMAL);

	UpdateData(TRUE);
	CString selectPath;
	GetDlgItemText(IDC_MFCEDITBROWSE4, selectPath);

	CString remote_file;
	GetDlgItemText(IDC_EDIT6, remote_file);

	//判断远程目录是否存在
	if (!isRemotePathexist(remote_file,1,sc.recv_sock,sc.recv_session))
	{
		GetDlgItem(IDC_BUTTON6)->EnableWindow(TRUE);
		m_recv_process.ShowWindow(SW_HIDE);
		RefreshSession(sc.recv_sock, sc.recv_session);
		if (MessageBox("下载失败，是否重新下载!", "提示", MB_YESNO) == IDYES)
		{
			OnBnClickedButton6();
		}
		return;
	}



	if (!PathIsDirectory(selectPath))
	{
		MessageBox("本地文件夹不存在!\n");
		return;
	}

	CString Filename = SpliteFileName(remote_file);
	Filename = "\\" + Filename;
	CString Target = selectPath + Filename;
	//sc.recv_file_vid_scp(m_remote_file, Target);

	//下载文件
	//My_SendFile(selectPath);
	//线程

	lp* sf = (lp*)malloc(sizeof(lp));
	sf->m_p = this;

	sf->selectPath = (char *)malloc(Target.GetLength() + 1);
	memset(sf->selectPath, 0, Target.GetLength() + 1);
	char *tmp = NULL;
	CStringA TMP_selectPath = Target;
	tmp = TMP_selectPath.GetBuffer();
	strcpy(sf->selectPath, tmp);
	CreateThread(NULL, 0, Thread_Begin_Download,
		(LPVOID)sf, NULL, NULL);


	/*CWinThread* AFXAPI AfxBeginThread(AFX_THREADPROC pfnThreadProc, LPVOID pParam,
		int nPriority = THREAD_PRIORITY_NORMAL, UINT nStackSize = 0,
		DWORD dwCreateFlags = 0, LPSECURITY_ATTRIBUTES lpSecurityAttrs = NULL);*/
}

void CWinSCPView::DownloadFile(CString hostTarget)
{
	if (TRUE == sc.recv_file_vid_scp(m_remote_file, hostTarget, m_recv_process))
		MessageBox("下载成功!");
	else
		MessageBox("下载失败!");
	m_recv_process.ShowWindow(TRUE);
}




void CWinSCPView::RefreshSession(int sock_option, LIBSSH2_SESSION *session_option)
{
	sc.Release(sock_option, session_option);
	if (!sc.Initssh())
	{
		MessageBox("init error\n");
		return;
	}
	if (!sc.CreateSock(sock_option))
	{
		MessageBox("Create socket error!\n");
		sc.Release(sock_option, session_option);
		return;
	}
	if (!sc.Connect(sock_option))
	{
		MessageBox("Connect error\n");
		sc.Release(sock_option, session_option);
		return;
	}
	if (!sc.CreateSession(&session_option))
	{
		MessageBox("create session error!\n");
		sc.Release(sock_option, session_option);
		return;
	}
	if (!sc.StartupConnect(sock_option, session_option))
	{
		MessageBox("Failure establishing SSH session\n");
		sc.Release(sock_option, session_option);
		return;
	}
	int rs = 0;
	if ((rs = sc.AuthenticateIdentity(session_option)) != 0)
	{
		if (rs == PUBLICKEYERROR)
		{
			MessageBox("AuthenticateIdentity error!\nPublic key error");
		}
		else
		{
			MessageBox("AuthenticateIdentity error!\nUsername or PassWords Error!\n");
		}
		sc.Release(sock_option, session_option);
		return;
	}
}


//重新启动程序
void CWinSCPView::OnClose()
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	char pBuf[MAX_PATH];
	//获取应用程序完全路径，比 GetCurrentDirectory 好用多了
	GetModuleFileName(NULL, pBuf, MAX_PATH);

	STARTUPINFO startupinfo;
	PROCESS_INFORMATION proc_info;
	memset(&startupinfo, 0, sizeof(STARTUPINFO));
	startupinfo.cb = sizeof(STARTUPINFO);
	// 最重要的地方
	if (m_bSetRestart)
		::CreateProcess(pBuf, NULL, NULL, NULL, FALSE,
			NORMAL_PRIORITY_CLASS, NULL, NULL, &startupinfo, &proc_info);
	exit(0);
	//CFormView::OnClose();
}


void CWinSCPView::OnBnClickedButton7()
{
	// TODO: 在此添加控件通知处理程序代码
	m_bSetRestart = true;//控制是否重新运行的变量
	this->SendMessage(WM_CLOSE);
}
