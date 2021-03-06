// CLoginDIalog.cpp: 实现文件
//

#include "stdafx.h"
#include "WinSCP.h"
#include "CLoginDIalog.h"
#include "afxdialogex.h"
#include "WinScpView.h"



ScpProtocol sc;


// CLoginDIalog 对话框

IMPLEMENT_DYNAMIC(CLoginDIalog, CDialogEx)

CLoginDIalog::CLoginDIalog(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_LOGINDIALOG, pParent)
	, mv_Username(_T("gaojie"))
	, mv_PassWord(_T("gaojie123"))
	, mV_port(65534)
{
}

CLoginDIalog::~CLoginDIalog()
{
}

void CLoginDIalog::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, m_combo);
	DDX_Control(pDX, IDC_IPADDRESS1, m_ip);
	//  DDX_Text(pDX, IDC_EDIT2, mV_Port);
	DDX_Text(pDX, IDC_EDIT1, mv_Username);
	DDX_Text(pDX, IDC_EDIT3, mv_PassWord);
	DDX_Control(pDX, IDC_BUTTON1, m_buttonLogin);
	DDX_Control(pDX, IDC_BUTTON2, m_buttonExit);
	DDX_Text(pDX, IDC_EDIT2, mV_port);
}


BEGIN_MESSAGE_MAP(CLoginDIalog, CDialogEx)
	ON_WM_CLOSE()
	ON_BN_CLICKED(IDC_BUTTON2, &CLoginDIalog::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON1, &CLoginDIalog::OnBnClickedButton1)
	ON_WM_MOVE()
	ON_EN_CHANGE(IDC_EDIT2, &CLoginDIalog::OnEnChangeEdit2)
END_MESSAGE_MAP()


// CLoginDIalog 消息处理程序





BOOL CLoginDIalog::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化
	CRect rcDlgs;
	GetWindowRect(rcDlgs);  //得到对话框的Rect 对话框的大小
	ScreenToClient(rcDlgs);            //把屏幕的值转成相应的实际的值

	int  cx = GetSystemMetrics(SM_CXSCREEN);  //获得屏幕的分辨率
	int  cy = GetSystemMetrics(SM_CYSCREEN);

	SetWindowPos(&wndTopMost, (cx - rcDlgs.Width())/2, (cy - rcDlgs.Height())/2, rcDlgs.Width(), rcDlgs.Height(), SWP_NOSIZE);
	
	MyInitDialog();




	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}

void CLoginDIalog::MyInitDialog()
{
	//CenterWindow();

	m_combo.AddString("SCP");
	//m_combo.AddString("SFTP");
	m_combo.SetCurSel(0);

	/*CString IpValue;
	IpValue = "120.77.203.15";
	SetDlgItemTextA(IDC_IPADDRESS1, IpValue);*/

	CEdit *e_Port = (CEdit*)this->GetDlgItem(IDC_EDIT2);
	e_Port->SetLimitText(5);


	//读取配置文件更新控件的值
	ReadConfigFile();
}


//退出按钮
void CLoginDIalog::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	sc.Release(sc.sock, sc.session);
	sc.Release(sc.recv_sock, sc.recv_session);
	exit(0);
}

void CLoginDIalog::OnClose()
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	//退出整个程序
	CDialogEx::OnClose();
	
	sc.Release(sc.sock, sc.session);
	sc.Release(sc.recv_sock, sc.recv_session);
	exit(0);
		
}

//登陆按钮
void CLoginDIalog::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	//测试方便先注释,我在初始化时候直接写进去了ip值。
	UpdateData(TRUE);
	
	


	CString IpValue;
	GetDlgItemTextA(IDC_IPADDRESS1, IpValue);
	
	

	sc.SetVal(IpValue, mV_port, mv_Username, mv_PassWord);
	if (!sc.Initssh())
	{
		MessageBox("init error\n");
		return;
	}
	if (!sc.CreateSock(sc.sock) || !sc.CreateSock(sc.recv_sock))
	{
		MessageBox("Create socket error!\n");
		sc.Release(sc.sock,sc.session);
		sc.Release(sc.recv_sock, sc.recv_session);
		return;
	}
	if (!sc.Connect(sc.sock) || !sc.Connect(sc.recv_sock))
	{
		MessageBox("Connect error\n");
		sc.Release(sc.sock, sc.session);
		sc.Release(sc.recv_sock, sc.recv_session);
		return;
	}
	if (!sc.CreateSession(&sc.session) || !sc.CreateSession(&sc.recv_session))
	{
		MessageBox("create session error!\n");
		sc.Release(sc.sock, sc.session);
		sc.Release(sc.recv_sock, sc.recv_session);
		return;
	}
	if (!sc.StartupConnect(sc.sock,sc.session) || !sc.StartupConnect(sc.recv_sock,sc.recv_session))
	{
		MessageBox("Failure establishing SSH session\n");
		sc.Release(sc.sock, sc.session);
		sc.Release(sc.recv_sock, sc.recv_session);
		return;
	}
	int rs = 0;
	if (((rs = sc.AuthenticateIdentity(sc.session)) != 0) || 
		((rs = sc.AuthenticateIdentity(sc.recv_session)) != 0))
	{
		if (rs == PUBLICKEYERROR)
		{
			MessageBox("AuthenticateIdentity error!\nPublic key error");
		}
		else
		{
			MessageBox("AuthenticateIdentity error!\nUsername or PassWords Error!\n");
		}
		sc.Release(sc.sock, sc.session);
		sc.Release(sc.recv_sock, sc.recv_session);
		return;
	}




	WriteConfigFile();
	MessageBox("成功连接!\n");
	//关闭当前模态对话框
	EndDialog(0);
}

//防止回车和ESC键关闭当前模态窗口
BOOL CLoginDIalog::PreTranslateMessage(MSG* pMsg)
{
	// TODO: 在此添加专用代码和/或调用基类
	if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_ESCAPE)return TRUE;
	if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_RETURN)
	{
		OnBnClickedButton1();
		return TRUE;
	}
	else
	return CDialogEx::PreTranslateMessage(pMsg);
}


void CLoginDIalog::OnMove(int x, int y)
{
	CDialogEx::OnMove(x, y);

	// TODO: 在此处添加消息处理程序代码
	CWinSCPView *parent = (CWinSCPView*)GetParent();

	if (parent && ::IsWindow(parent->m_hWnd))
	{
		CRect prect,crect;
		parent->GetWindowRect(prect);
GetWindowRect(crect);
int posx = x - ((prect.Width() - crect.Width()) / 2);
int posy = y + ((prect.Height() - prect.Height()) / 2);
parent->SetWindowPos(NULL, posx, posy, prect.Width(), prect.Height(), SWP_SHOWWINDOW);
	}

}




void CLoginDIalog::OnEnChangeEdit2()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
	CEdit *p_port = (CEdit*)GetDlgItem(IDC_EDIT2);
	CString port_content;
	p_port->GetWindowText(port_content);
	int intNo = _tstoi(port_content);
	CString sNo;
	sNo.Format(_T("%d"), intNo);
	if (sNo != port_content)
	{
		p_port->SetWindowText(sNo);
		int position = sNo.GetLength();
		p_port->SetSel(position, position, FALSE);
		return;
	}

	UpdateData(TRUE);
	if (mV_port < 0 || mV_port > 65535)
	{
		MessageBox("端口的范围为0~65535\n");
		if (mV_port > 65535)
		{
			mV_port = 65535;
		}
		else
		{
			mV_port = 1;
		}
		UpdateData(FALSE);
		return;
	}
}

void CLoginDIalog::WriteConfigFile()
{
	int rs = 0;
	if (!(PathFileExists("config.ini")))
		rs = MessageBox("配置文件未存在是否将本次登录信息存入?", "提示", MB_YESNO);
	//else
		//rs = MessageBox("是否将本次登录信息存入?", "提示", MB_YESNO);
	if (rs == IDNO)
	{
		return;
	}
	FILE *fp = fopen("config.ini", "w+");//w+打开文件，若存在文件则清空文件。
	if (fp == NULL)
	{
		MessageBox("打开配置文件错误!\n请确保文件未被其他程序占用\n");
		return;
	}
	//IpValue, mV_port, mv_Username, mv_PassWord
	CString IpValue;
	GetDlgItemTextA(IDC_IPADDRESS1, IpValue);
	CString BufToFile;
	BufToFile.Format("%s|%d|%s|%s", IpValue, mV_port, mv_Username, mv_PassWord);
	fwrite(BufToFile, sizeof(char), BufToFile.GetLength(), fp);

	fclose(fp);


}

void CLoginDIalog::ReadConfigFile()
{
	if (!PathFileExists("config.ini"))
		return;
	FILE *fp = fopen("config.ini", "r");
	if (fp == NULL)
	{
		return;
	}
	fseek(fp, 0, SEEK_END);
	int filesize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	char *buf = (char*)malloc(sizeof(char)*filesize + 1);
	memset(buf, 0, filesize);

	fread(buf, sizeof(char), filesize, fp);
	buf[filesize] = '\0';
	CString getbuff;
	getbuff.Format("%s", buf);

	free(buf);
	buf == nullptr;

	int po = 0;

	if ((po = getbuff.Find("|")) != -1)
	{
		CString mv_IP;
		mv_IP = getbuff.Left(po);
		getbuff = getbuff.Right(filesize - po - 1);
		SetDlgItemText(IDC_IPADDRESS1, mv_IP);
		filesize = getbuff.GetLength();
	}
	else
	{
		MessageBox("配置文件损坏!");
	}
	
	if ((po = getbuff.Find("|")) != -1)
	{
		CString mv_port;
		mv_port = getbuff.Left(po);
		getbuff = getbuff.Right(filesize - po - 1);
		SetDlgItemText(IDC_EDIT2, mv_port);
		filesize = getbuff.GetLength();
	}
	else
	{
		MessageBox("配置文件损坏!");
	}

	if ((po = getbuff.Find("|")) != -1)
	{
		CString mv_username;
		mv_username = getbuff.Left(po);
		getbuff = getbuff.Right(filesize - po - 1);
		SetDlgItemText(IDC_EDIT1, mv_username);
		filesize = getbuff.GetLength();
	}
	else
	{
		MessageBox("配置文件损坏!");
	}
	SetDlgItemText(IDC_EDIT3, getbuff);

	fclose(fp);
	
}

