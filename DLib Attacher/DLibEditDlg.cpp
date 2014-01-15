// DLibEditDlg.cpp : implementation file
//

#include "stdafx.h"
#include "DLibEditDlg.h"
#include "afxdialogex.h"
#include "DLibAttacherDlg.h"

// DLibEditDlg dialog

IMPLEMENT_DYNAMIC(DLibEditDlg, CDialogEx)

DLibEditDlg::DLibEditDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(DLibEditDlg::IDD, pParent)
{
	_parent = pParent;
}

DLibEditDlg::~DLibEditDlg()
{
}

void DLibEditDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, textLibName);
	DDX_Control(pDX, IDC_EDIT5, textLibProc);
	DDX_Control(pDX, IDC_CHECK3, checkProcEnable);
	DDX_Control(pDX, IDC_CHECK4, checkProcRetn);
}


BEGIN_MESSAGE_MAP(DLibEditDlg, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON1, &DLibEditDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON8, &DLibEditDlg::OnBnClickedButton8)
//	ON_WM_ACTIVATE()
ON_BN_CLICKED(IDC_CHECK3, &DLibEditDlg::OnBnClickedCheck3)
END_MESSAGE_MAP()


// DLibEditDlg message handlers


void DLibEditDlg::OnBnClickedButton1()
{
	EndDialog(IDCANCEL);
}


void DLibEditDlg::OnBnClickedButton8()
{
	CDLibAttacherDlg *prnt = (CDLibAttacherDlg *)_parent;
	Edit_Type type;
	PDLibs_Struct lib;
	CString str;

	if (prnt) {
		textLibName.GetWindowTextW(str);
		if (str.GetLength() == 0) {
			MessageBoxA(0, "Enter library name!", "Warning", MB_ICONWARNING);
			return;
		}
		lib.dll = str;
		lib.use_proc = checkProcEnable.GetCheck();
		lib.chk_retn = (lib.use_proc && checkProcRetn.GetCheck() ? true : false);
		textLibProc.GetWindowTextW(str);
		if (lib.use_proc && str.GetLength() == 0) {
			MessageBoxA(0, "Enter procedure name!", "Warning", MB_ICONWARNING);
			return;
		}
		lib.proc = str;

		type = prnt->GetEditorType();
		if (type == EDT_ADD) {
			prnt->AddLibrary(lib);
		} else if (type == EDT_EDIT) {
			prnt->EditLibrary(prnt->GetEditorId(), lib);
		}
	}
	EndDialog(IDOK);
}



BOOL DLibEditDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	CDLibAttacherDlg *prnt = (CDLibAttacherDlg *)_parent;
	PDLibs_Struct lib;
	if (prnt->GetEditorType() == EDT_EDIT) {
		prnt->GetEditorElem(lib);
		textLibName.SetWindowTextW(lib.dll);
		textLibProc.SetWindowTextW(lib.proc);
		checkProcEnable.SetCheck(lib.use_proc);
		if (lib.use_proc && lib.chk_retn) {
			checkProcRetn.SetCheck(true);
			checkProcRetn.EnableWindow(true);
		} else {
			checkProcRetn.SetCheck(false);
			checkProcRetn.EnableWindow(true);
		}
	} else {
		checkProcEnable.SetCheck(false);
		checkProcRetn.SetCheck(false);
		checkProcRetn.EnableWindow(false);
	}

	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}


void DLibEditDlg::OnBnClickedCheck3()
{
	checkProcRetn.EnableWindow((bool)checkProcEnable.GetCheck());
}
