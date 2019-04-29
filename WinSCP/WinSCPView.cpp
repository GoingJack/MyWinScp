
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
{
	// TODO: 在此处添加构造代码

}

CWinSCPView::~CWinSCPView()
{
}

void CWinSCPView::DoDataExchange(CDataExchange* pDX)
{
	CFormView::DoDataExchange(pDX);
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
	CString selectPath;
	GetDlgItemText(IDC_MFCEDITBROWSE1, selectPath);
	if (!PathFileExists(selectPath))
	{
		MessageBox("文件不存在!\n");
	}
	int rs = sc.SendFile(selectPath, "/tmp/1.txt");
	if (rs == 0)
	{
		MessageBox("传送成功!\n");
	}
}
