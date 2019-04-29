// CLoginDIalog.cpp: 实现文件
//

#include "stdafx.h"
#include "WinSCP.h"
#include "CLoginDIalog.h"
#include "afxdialogex.h"



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
END_MESSAGE_MAP()


// CLoginDIalog 消息处理程序





BOOL CLoginDIalog::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化
	MyInitDialog();




	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}

void CLoginDIalog::MyInitDialog()
{
	m_combo.AddString("SCP");
	m_combo.AddString("SFTP");
	m_combo.SetCurSel(0);
}


//退出按钮
void CLoginDIalog::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	sc.Release();
	exit(0);
}

void CLoginDIalog::OnClose()
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	//退出整个程序
	CDialogEx::OnClose();
	
	sc.Release();
	exit(0);
		
}

//登陆按钮
void CLoginDIalog::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateData(TRUE);
	CString IpValue;
	GetDlgItemTextA(IDC_IPADDRESS1, IpValue);
	
	

	sc.SetVal(IpValue, mV_port, mv_Username, mv_PassWord);
	if (!sc.Initssh())
	{
		MessageBox("init error\n");
		return;
	}
	if (!sc.CreateSock())
	{
		MessageBox("Create socket error!\n");
		return;
	}
	if (!sc.Connect())
	{
		MessageBox("Connect error\n");
		return;
	}
	if (!sc.CreateSession())
	{
		MessageBox("create session error!\n");
		return;
	}
	if (!sc.StartupConnect())
	{
		MessageBox("Failure establishing SSH session\n");
		return;
	}
	int rs = 0;
	if ((rs = sc.AuthenticateIdentity()) != 0)
	{
		if (rs == PUBLICKEYERROR)
		{
			MessageBox("AuthenticateIdentity error!\nPublic key error");
		}
		else
		{
			MessageBox("AuthenticateIdentity error!\nPassWords Error!\n");
		}
		sc.Release();
		return;
	}
	MessageBox("成功!\n");
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
