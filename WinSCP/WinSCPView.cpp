
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
#include "ScpProtocol.h"

extern ScpProtocol sc;

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
END_MESSAGE_MAP()

// CWinSCPView 构造/析构

CWinSCPView::CWinSCPView() noexcept
	: CFormView(IDD_WINSCP_FORM)
	,mv_remotePath(_T("/tmp/"))
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


void CWinSCPView::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateData(TRUE);
	CString selectPath;
	GetDlgItemText(IDC_MFCEDITBROWSE1, selectPath);
	if (!PathFileExists(selectPath))
	{
		MessageBox("文件不存在!\n");
	}

	//判断远程目录是否存在
	if (!isRemotePathexist())
		return;

	//发送文件
	My_SendFile(selectPath);
	
}

CString CWinSCPView::SpliteFileName(const CString & selectfilepath)
{
	CFile spliter;
	spliter.SetFilePath(selectfilepath);

	return spliter.GetFileName();
}

//可以判断命令是否执行成功的执行命令，二次封装函数
BOOL CWinSCPView::execACommand(const char * commandline)
{
	if (nullptr == commandline)return false;
	char commandCatReturn[128] = { 0 };
	sprintf(commandCatReturn, "%s;echo $?", commandline);
	CString result;
	int res = sc.execOneCommand(commandCatReturn, result);
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

BOOL CWinSCPView::isRemotePathexist()
{
	char isexist[128] = { 0 };
	sprintf(isexist, "ls %s", mv_remotePath);
	CString exec_result;
	int resfromexec = sc.execOneCommand(isexist, exec_result);
	if (resfromexec == CHANNELERROR)
	{
		MessageBox("channel error!\n");
		return false;
	}
	else if (resfromexec == EXECERROR)
	{
		MessageBox("exec fun error!\n");
		return false;
	}
	else if (resfromexec == ERRORCOMMAND)
	{
		if(MessageBox("remote path is not exist,command exec output is stderr!\n would you like to create it?","warnning!!!",MB_YESNO)==MB_OK);
		{
			char MDcommand[128] = { 0 };
			sprintf(MDcommand, "mkdir -p %s", mv_remotePath);
			CString result;
			if (execACommand(MDcommand))//创建成功目录后返回结果为0，故不能通过有没有返回内容来判断是否成功创建
			{
				MessageBox("创建成功!\n");
				return true;
			}
		}
		return false;
	}
	else return true;
}

void CWinSCPView::My_SendFile(CString selectPath)
{
	if (mv_remotePath.Right(1) != "/")
		mv_remotePath += "/";
	CString remotePathCatFilename = mv_remotePath + SpliteFileName(selectPath);
	int rs = sc.SendFile(selectPath, remotePathCatFilename);
	if (rs == OPENFILEERROR)
	{
		char localfileerror[1024];
		sprintf(localfileerror, "打开 %s 文件失败\n", selectPath);
		MessageBox(localfileerror);
	}
	else if (rs == CANNOTOPENS)
	{
		MessageBox("打开session失败\n");
	}
	else if (rs == SENDERROR)
	{
		MessageBox("发送失败\n");
	}
	else if (rs == 0)
	{
		MessageBox("传送成功!\n");
	}
}
