#pragma once
#include "ScpProtocol.h"


// CLoginDIalog 对话框

class CLoginDIalog : public CDialogEx
{
	DECLARE_DYNAMIC(CLoginDIalog)

public:
	CLoginDIalog(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CLoginDIalog();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum {
		IDD = IDD_LOGINDIALOG
};
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnClose();
	CComboBox m_combo;
	CIPAddressCtrl m_ip;
	CString mv_Username;
	CString mv_PassWord;
	CButton m_buttonLogin;
	CButton m_buttonExit;
	virtual BOOL OnInitDialog();

	// 添加自己的初始化函数
	void MyInitDialog();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton1();
	int mV_port;
	//添加建立连接的scp对象
	
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	afx_msg void OnMove(int x, int y);
	afx_msg void OnEnChangeEdit2();

	//写入配置文件
	void WriteConfigFile();
	//读取配置文件
	void ReadConfigFile();
};
