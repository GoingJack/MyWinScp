
// WinSCPView.h: CWinSCPView 类的接口
//

#pragma once
#include "WinSCPDoc.h"
#include "ScpProtocol.h"


class CWinSCPView : public CFormView
{
protected: // 仅从序列化创建
	CWinSCPView() noexcept;
	DECLARE_DYNCREATE(CWinSCPView)

public:
#ifdef AFX_DESIGN_TIME
	enum{ IDD = IDD_WINSCP_FORM };
#endif

// 特性
public:
	CWinSCPDoc* GetDocument() const;

// 操作
public:

// 重写
public:
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	virtual void OnInitialUpdate(); // 构造后第一次调用
	virtual BOOL OnPreparePrinting(CPrintInfo* pInfo);
	virtual void OnBeginPrinting(CDC* pDC, CPrintInfo* pInfo);
	virtual void OnEndPrinting(CDC* pDC, CPrintInfo* pInfo);
	virtual void OnPrint(CDC* pDC, CPrintInfo* pInfo);

// 实现
public:
	virtual ~CWinSCPView();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

protected:

// 生成的消息映射函数
protected:
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	//分割选择的路径---->文件名字
	CString SpliteFileName(const CString &selectfilepath);
	//远程目录
	CString mv_remotePath;
	
	//再次封装执行命令，可以判断命令执行后的状态成功或者失败
	BOOL execACommand(const char *commandline, CString &ShowResult);

	//判断远程目录是否存在
	BOOL isRemotePathexist(CString Apath, int mode, int sock_option, LIBSSH2_SESSION * session_option);

	//发送文件，二次封装为了适应交互。
	bool My_SendFile(CString selectpath);

	//命令交互界面
	//CListBox m_showlist;
	CString m_commandline;
	void ExecAndShow();

	//焦点在编辑框时按回车执行命令。
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton4();
	CRichEditCtrl m_richedit1;
	afx_msg void OnBnClickedButton5();


	//
	CProgressCtrl m_send_process;
	afx_msg void OnBnClickedButton6();
	CProgressCtrl m_recv_process;

//	CMFCEditBrowseCtrl m_recv_path;
	CString m_remote_file;

	void DownloadFile(CString hostDir);


	//重启
	bool m_bSetRestart;
	afx_msg void OnClose();
	afx_msg void OnBnClickedButton7();

	//刷新session
	void RefreshSession(int sock_option,LIBSSH2_SESSION *session_option);
};

#ifndef _DEBUG  // WinSCPView.cpp 中的调试版本
inline CWinSCPDoc* CWinSCPView::GetDocument() const
   { return reinterpret_cast<CWinSCPDoc*>(m_pDocument); }
#endif

