
// DLibAttacherDlg.h : header file
//

#pragma once
#include "afxwin.h"
#include "DLibAttach.h"

#include <list>
#include "afxcmn.h"

enum Disable_Ctrl {
	DC_ALL,
	DC_ADD_LIB,
	DC_EDIT_LIB,
	DC_DEL_LIB,
	DC_ATTACH,
	DC_DETTACH,
};

enum Edit_Type {
	EDT_NONE,
	EDT_ADD,
	EDT_EDIT
};

typedef struct {
	DWORD guid;
	CString dll;
	CString proc;
	bool use_proc;
	bool chk_retn;
} PDLibs_Struct;

#define MAX_MESSAGE_SIZE 500
#define MAX_DLL_COUNT 50

// CDLibAttacherDlg dialog
class CDLibAttacherDlg : public CDialogEx
{
	UINT _guid;
	Edit_Type _edit_type;
	UINT _edit_id;

	std::list<PDLibs_Struct> _dlib;

	CDLibShellAttach _att;
	void EnableControl(Disable_Ctrl ctrl, bool type);

	void ClearLibList();
	void RedrawLibList();

// Construction
public:
	CDLibAttacherDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_DLIBATTACHERV10A_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support

public:
	bool OpenAppFile(PVOID wpath);
	int AddLibrary(PDLibs_Struct &lib);
	bool EditLibrary(int id, PDLibs_Struct &lib);
	void RemoveLibrary(int id);
	Edit_Type GetEditorType();
	int GetEditorId();
	bool GetEditorElem(PDLibs_Struct &lib);
	bool MakeBackup();
	bool RestoreBackup();
// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton6();
	CEdit errorBox1;
	CEdit errorBox2;
	CEdit errorBox3;
	CButton checkBakup;
	CButton checkCrc;
	afx_msg void OnNMClickSyslink1(NMHDR *pNMHDR, LRESULT *pResult);
	CButton btnAddLib;
	CButton btnEditLib;
	CButton btnDelLib;
	CButton btnAttach;
	CButton btnDettach;
	afx_msg void OnBnClickedButton1();
	CEdit textApp;
	afx_msg void OnEnUpdateEdit1();
	afx_msg void OnBnClickedButton2();
	CListBox listLnkDll;
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton7();
	afx_msg void OnLbnSelchangeList2();
	afx_msg void OnBnClickedButton5();
	afx_msg void OnBnClickedButton4();
	CComboBox comboRun;
	CLinkCtrl linkAdv;
};
