
// WinSCPView.h: CWinSCPView 类的接口
//

#pragma once


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
};

#ifndef _DEBUG  // WinSCPView.cpp 中的调试版本
inline CWinSCPDoc* CWinSCPView::GetDocument() const
   { return reinterpret_cast<CWinSCPDoc*>(m_pDocument); }
#endif

