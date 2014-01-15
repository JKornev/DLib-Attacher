#pragma once

#include "resource.h"
#include "afxwin.h"
// DLibEditDlg dialog

class DLibEditDlg : public CDialogEx
{
	CWnd* _parent;
	DECLARE_DYNAMIC(DLibEditDlg)

public:
	DLibEditDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~DLibEditDlg();

// Dialog Data
	enum { IDD = IDD_FORMVIEW };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton8();
	CEdit textLibName;
	CEdit textLibProc;
	CButton checkProcEnable;
//	afx_msg void OnActivate(UINT nState, CWnd* pWndOther, BOOL bMinimized);
	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedCheck3();
	CButton checkProcRetn;
};
