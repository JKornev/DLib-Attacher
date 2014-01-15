// DLibAttacherDlg.cpp : implementation file
//

#include "stdafx.h"
#include "DLibAttacher.h"
#include "DLibAttacherDlg.h"
#include "afxdialogex.h"
#include "DLibEditDlg.h"
#include "DLibAttach.h"
#include <ctime>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define ATTACH_TYPE_EP L"EntryPoint"
#define ATTACH_TYPE_TLS L"TLS Callback"
#define ATTACH_TYPE_DLL_EP L"DllMain(EP)"

#define MSGBOX_TITLE "Attach"

// CDLibAttacherDlg dialog

CDLibAttacherDlg::CDLibAttacherDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CDLibAttacherDlg::IDD, pParent), _guid(0)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CDLibAttacherDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT2, errorBox1);
	DDX_Control(pDX, IDC_EDIT3, errorBox2);
	DDX_Control(pDX, IDC_EDIT4, errorBox3);
	DDX_Control(pDX, IDC_CHECK1, checkBakup);
	DDX_Control(pDX, IDC_CHECK2, checkCrc);
	DDX_Control(pDX, IDC_BUTTON2, btnAddLib);
	DDX_Control(pDX, IDC_BUTTON3, btnEditLib);
	DDX_Control(pDX, IDC_BUTTON7, btnDelLib);
	DDX_Control(pDX, IDC_BUTTON4, btnAttach);
	DDX_Control(pDX, IDC_BUTTON5, btnDettach);
	DDX_Control(pDX, IDC_EDIT1, textApp);
	DDX_Control(pDX, IDC_LIST2, listLnkDll);
	DDX_Control(pDX, IDC_COMBO1, comboRun);
	DDX_Control(pDX, IDC_SYSLINK1, linkAdv);
}

BEGIN_MESSAGE_MAP(CDLibAttacherDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON6, &CDLibAttacherDlg::OnBnClickedButton6)
	ON_NOTIFY(NM_CLICK, IDC_SYSLINK1, &CDLibAttacherDlg::OnNMClickSyslink1)
	ON_BN_CLICKED(IDC_BUTTON1, &CDLibAttacherDlg::OnBnClickedButton1)
	ON_EN_UPDATE(IDC_EDIT1, &CDLibAttacherDlg::OnEnUpdateEdit1)
	ON_BN_CLICKED(IDC_BUTTON2, &CDLibAttacherDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CDLibAttacherDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON7, &CDLibAttacherDlg::OnBnClickedButton7)
	ON_LBN_SELCHANGE(IDC_LIST2, &CDLibAttacherDlg::OnLbnSelchangeList2)
	ON_BN_CLICKED(IDC_BUTTON5, &CDLibAttacherDlg::OnBnClickedButton5)
	ON_BN_CLICKED(IDC_BUTTON4, &CDLibAttacherDlg::OnBnClickedButton4)
END_MESSAGE_MAP()


// CDLibAttacherDlg message handlers

BOOL CDLibAttacherDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	errorBox1.SetWindowTextW(L"Failed to load library %s, error code %d");
	errorBox2.SetWindowTextW(L"Failed to process library %s, error code %d");
	errorBox3.SetWindowTextW(L"Failed to startup library %s, error code %d");

	checkBakup.SetCheck(1);
	checkCrc.SetCheck(1);

/*	if (!CopyFileW(
		L"c:\\Users\\JKornev\\Documents\\Visual Studio 2010\\Projects\\PE DLib Shellcode\\Release\\PE DLib Shellcode - Copy.exe", 
		L"c:\\Users\\JKornev\\Documents\\Visual Studio 2010\\Projects\\PE DLib Shellcode\\Release\\PE DLib Shellcode.exe", 
		false)) {
	}*/

	comboRun.AddString(ATTACH_TYPE_EP);
	comboRun.AddString(ATTACH_TYPE_TLS);
	comboRun.SelectString(-1, ATTACH_TYPE_TLS);

	EnableControl(DC_ALL, false);
	EnableControl(DC_ADD_LIB, true);

	//advertising
	/*srand(time(NULL));
	int type = rand() % 5;
	switch (type) {
	case 1:
		linkAdv.SetWindowTextW(L"<a>Looking good anti-cheat?</a>");
		break;
	case 2:
		linkAdv.SetWindowTextW(L"<a>Do you need some drugs?)</a>");
		break;
	case 3:
		linkAdv.SetWindowTextW(L"<a>Watch free lesbian porn :)</a>");
		break;
	case 4:
		linkAdv.SetWindowTextW(L"<a>Click at me hacker!</a>");
		break;
	default:
		linkAdv.SetWindowTextW(L"<a>Visit our website www.anti-cheat.ru</a>");
		break;
	}*/
	linkAdv.SetWindowTextW(L"<a>http://k0rnev.blogspot.com</a>");

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CDLibAttacherDlg::EnableControl(Disable_Ctrl ctrl, bool type)
{
	if (ctrl == DC_ALL || ctrl == DC_ADD_LIB) {
		btnAddLib.EnableWindow(type);
	}
	if (ctrl == DC_ALL || ctrl == DC_EDIT_LIB) {
		btnEditLib.EnableWindow(type);
	} 
	if (ctrl == DC_ALL || ctrl == DC_DEL_LIB) {
		btnDelLib.EnableWindow(type);
	} 
	if (ctrl == DC_ALL || ctrl == DC_ATTACH) {
		btnAttach.EnableWindow(type);
	} 
	if (ctrl == DC_ALL || ctrl == DC_DETTACH) {
		btnDettach.EnableWindow(type);
	}
}

void CDLibAttacherDlg::OnPaint()
{
	if (IsIconic()) {
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	} else {
		CDialogEx::OnPaint();
	}
}

HCURSOR CDLibAttacherDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CDLibAttacherDlg::OnBnClickedButton6()
{
	exit(0);
}

void CDLibAttacherDlg::OnNMClickSyslink1(NMHDR *pNMHDR, LRESULT *pResult)
{
	ShellExecuteA(NULL, "open", "http://k0rnev.blogspot.com", NULL, NULL, SW_SHOWNORMAL);
	*pResult = 0;
}

void CDLibAttacherDlg::OnBnClickedButton1()
{
	CString str;

	CFileDialog CFile(true, L".exe", L"", 0, L"PE Applications (exe, dll)|*.exe;*.dll|All Files (*.*)|*.*||");
	INT_PTR result = CFile.DoModal();
	if (result != IDOK) {
		return;
	}

	str = CFile.GetPathName();

	if (!OpenAppFile(str.GetBuffer())) {
		return;
	}

	textApp.SetWindowTextW(CFile.GetPathName());
}

void CDLibAttacherDlg::OnEnUpdateEdit1()
{
	if (!btnAttach.IsWindowEnabled() && textApp.GetWindowTextLengthW() > 0) {
		EnableControl(DC_ATTACH, true);
	}
}

void CDLibAttacherDlg::OnBnClickedButton2()
{//Add lib
	DLibEditDlg dlg(this);
	_edit_type = EDT_ADD;
	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK) {

	} else if (nResponse == IDCANCEL) {

	}
}

void CDLibAttacherDlg::OnBnClickedButton3()
{//Edit lib
	DLibEditDlg dlg(this);
	_edit_type = EDT_EDIT;
	INT_PTR nResponse;
	bool found = false;

	for (int i = 0; i < listLnkDll.GetCount(); i++) {
		if (listLnkDll.GetSel(i) > 0) {
			found = true;
			_edit_id = i;
			break;
		}
	}
	if (!found) {
		return;
	}

	nResponse = dlg.DoModal();
	if (nResponse == IDOK) {

	} else if (nResponse == IDCANCEL) {

	}
}

void CDLibAttacherDlg::OnBnClickedButton7()
{//Remove lib
	for (int i = 0; i < listLnkDll.GetCount(); i++) {
		if (listLnkDll.GetSel(i) > 0) {
			RemoveLibrary(i);
		}
	}
}

void CDLibAttacherDlg::ClearLibList()
{
	_dlib.clear();
	listLnkDll.ResetContent();
	EnableControl(DC_DEL_LIB, false);
	EnableControl(DC_EDIT_LIB, false);
}

void CDLibAttacherDlg::RedrawLibList()
{
	std::list<PDLibs_Struct>::iterator it = _dlib.begin();
	wchar_t buff[MAX_MESSAGE_SIZE + 100];
	listLnkDll.ResetContent();

	while (it != _dlib.end()) {
		wsprintf(buff, L"%s [%s]", it->dll.GetBuffer(), (it->use_proc ? it->proc.GetBuffer() : L"none"));
		it->guid = listLnkDll.InsertString(-1, buff);
		it++;
	}
}

bool CDLibAttacherDlg::OpenAppFile(PVOID wpath)
{
	LPSTR msg;
	LPWSTR lpstr;
	int count, id;
	PShell_DllFrame pdll;
	PDLibs_Struct lib;

	EnableControl(DC_DETTACH, false);

	if (_att.IsShellOpen()) {
		_att.ClosePE();
	}
	ClearLibList();

	if (!_att.OpenPE(wpath)) {
		textApp.SetWindowTextW(L"");
		return false;
	}

	if (_att.IsAttached()) {
		EnableControl(DC_DETTACH, true);

		if (_att.GetFlag(SF_CRC32)) {
			checkCrc.SetCheck(1);
		} else {
			checkCrc.SetCheck(0);
		}

		lpstr = new wchar_t[MAX_MESSAGE_SIZE];
		msg = _att.GetErrorMessage(SE_SYSTEM_FAIL);
		if (msg) {
			mbstowcs(lpstr, msg, MAX_MESSAGE_SIZE);
			errorBox1.SetWindowTextW(lpstr);
		}

		msg = _att.GetErrorMessage(SE_SYSTEM_FAIL2);
		if (msg) {
			mbstowcs(lpstr, msg, MAX_MESSAGE_SIZE);
			errorBox2.SetWindowTextW(lpstr);
		}

		msg = _att.GetErrorMessage(SE_LIBRARY_FAIL);
		if (msg) {
			mbstowcs(lpstr, msg, MAX_MESSAGE_SIZE);
			errorBox3.SetWindowTextW(lpstr);
		}

		pdll = new Shell_DllFrame[MAX_DLL_COUNT];
		if (_att.GetDllList(pdll, MAX_DLL_COUNT, &count)) {
			for (int i = 0; i < count; i++) {
				msg = (LPSTR)_att.GetShellResPtr(pdll[i].name_id, NULL);
				if (!msg) {
					continue;
				}
				mbstowcs(lpstr, msg, MAX_MESSAGE_SIZE);
				lib.dll = lpstr;
				lib.use_proc = false;
				lib.chk_retn = false;
				if (pdll[i].func_id != RES_INVALID_ID) {
					msg = (LPSTR)_att.GetShellResPtr(_CLEAR(pdll[i].func_id, 1), NULL);
					if (!msg) {
						continue;
					}
					mbstowcs(lpstr, msg, MAX_MESSAGE_SIZE);
					lib.use_proc = true;
					lib.proc = lpstr;
					lib.chk_retn = (bool)(pdll[i].func_id & SHELL_EXP_PROC_USE_RETN);
				}
				AddLibrary(lib);
			}
		}
		delete[] pdll;
		delete[] lpstr;
	} else {
		_att.SetFlag(SF_USE_EP, true);
	}

	comboRun.ResetContent();
	if (_att.GetFlag(SF_DLL)) {
		comboRun.AddString(ATTACH_TYPE_DLL_EP);
		comboRun.SelectString(-1, ATTACH_TYPE_DLL_EP);
	} else {
		comboRun.AddString(ATTACH_TYPE_EP);
		comboRun.AddString(ATTACH_TYPE_TLS);
		if (_att.GetFlag(SF_USE_EP)) {
			comboRun.SelectString(-1, ATTACH_TYPE_EP);
		} else {
			comboRun.SelectString(-1, ATTACH_TYPE_TLS);
		}
	}
	return true;
}

int CDLibAttacherDlg::AddLibrary(PDLibs_Struct &lib)
{
	lib.guid = 0;
	_dlib.push_back(lib);
	RedrawLibList();
	EnableControl(DC_DEL_LIB, true);
	return _dlib.size() - 1;
}

bool CDLibAttacherDlg::EditLibrary(int id, PDLibs_Struct &lib)
{
	std::list<PDLibs_Struct>::iterator it = _dlib.begin();
	while (it != _dlib.end()) {
		if (it->guid == id) {
			it->dll = lib.dll;
			it->proc = lib.proc;
			it->use_proc = lib.use_proc;
			it->chk_retn = lib.chk_retn;
			RedrawLibList();
			return true;
		}
		it++;
	}
	return false;
}

void CDLibAttacherDlg::RemoveLibrary(int id)
{
	std::list<PDLibs_Struct>::iterator it = _dlib.begin();
	while (it != _dlib.end()) {
		if (it->guid == id) {
			_dlib.erase(it);
			RedrawLibList();
			return;
		}
		it++;
	}
}

Edit_Type CDLibAttacherDlg::GetEditorType()
{
	return _edit_type;
}

int CDLibAttacherDlg::GetEditorId()
{
	return _edit_id;
}

bool CDLibAttacherDlg::GetEditorElem(PDLibs_Struct &lib)
{
	std::list<PDLibs_Struct>::iterator it = _dlib.begin();
	while (it != _dlib.end()) {
		if (it->guid == _edit_id) {
			lib.dll = it->dll;
			lib.proc = it->proc;
			lib.use_proc = it->use_proc;
			lib.chk_retn = it->chk_retn;
			lib.guid = lib.guid;
			return true;
		}
		it++;
	}
	return false;
}

bool CDLibAttacherDlg::MakeBackup()
{
	if (checkBakup.GetCheck()) {
		CString str, new_path;
		textApp.GetWindowTextW(str);
		new_path = str;
		new_path += ".back";
		if (!CopyFileW(str.GetBuffer(), new_path.GetBuffer(), false)) {
			return false;
		}
	}
	return true;
}

bool CDLibAttacherDlg::RestoreBackup()
{
	if (checkBakup.GetCheck()) {
		CString str, new_path;
		textApp.GetWindowTextW(str);
		new_path = str;
		new_path += ".back";
		if (!CopyFileW(new_path.GetBuffer(), str.GetBuffer(), false)) {
			return false;
		}
	}
	return true;
}

void CDLibAttacherDlg::OnLbnSelchangeList2()
{
	for (int i = 0; i < listLnkDll.GetCount(); i++) {
		if (listLnkDll.GetSel(i) > 0) {
			EnableControl(DC_EDIT_LIB, true);
			return;
		}
	}
	EnableControl(DC_EDIT_LIB, false);
}


void CDLibAttacherDlg::OnBnClickedButton5()
{//detach event
	CString str;
	if (_att.IsAttached()) {
		if (!MakeBackup()) {
			MessageBoxA(0, "Error, can't backup file!", MSGBOX_TITLE, MB_ICONWARNING);
			return;
		}

		textApp.GetWindowTextW(str);
		if (!_att.DetachShell()) {
			MessageBoxA(0, "Error, can't detach!", MSGBOX_TITLE, MB_ICONWARNING);
			_att.ClosePE();
			RestoreBackup();
		} else {
			MessageBoxA(0, "Detaching successful!", MSGBOX_TITLE, MB_ICONINFORMATION);
		}
		OpenAppFile(str.GetBuffer());
	}
}


void CDLibAttacherDlg::OnBnClickedButton4()
{//attach event
	std::list<PDLibs_Struct>::iterator it;
	LPSTR dllname, procname, msg;
	LPWSTR wdllname, wprocname;
	CString str;

	if (!MakeBackup()) {
		MessageBoxA(0, "Error, can't backup file!", MSGBOX_TITLE, MB_ICONWARNING);
		return;
	}

	_att.SetFlag(SF_ADVANCE, false);
	_att.SetFlag(SF_CRC32, checkCrc.GetCheck());

	msg = new char[MAX_MESSAGE_SIZE];
	errorBox1.GetWindowTextW(str);
	wcstombs(msg, str.GetBuffer(), MAX_MESSAGE_SIZE);
	_att.SetErrorMessage(SE_SYSTEM_FAIL, msg);

	errorBox2.GetWindowTextW(str);
	wcstombs(msg, str.GetBuffer(), MAX_MESSAGE_SIZE);
	_att.SetErrorMessage(SE_SYSTEM_FAIL2, msg);

	errorBox3.GetWindowTextW(str);
	wcstombs(msg, str.GetBuffer(), MAX_MESSAGE_SIZE);
	_att.SetErrorMessage(SE_LIBRARY_FAIL, msg);

	comboRun.GetWindowTextW(str);
	if (str == ATTACH_TYPE_EP) {
		_att.SetFlag(SF_USE_EP, true);
		_att.SetFlag(SF_TLS, false);
	} else {
		_att.SetFlag(SF_USE_EP, false);
		_att.SetFlag(SF_TLS, true);
	}

	delete[] msg;

	if (_dlib.size() == 0) {
		MessageBoxA(0, "Error, add link library!", MSGBOX_TITLE, MB_ICONWARNING);
		return;
	}

	dllname = new char[MAX_MESSAGE_SIZE];
	procname = new char[MAX_MESSAGE_SIZE];
	_att.RemoveAllDll();
	it = _dlib.begin();
	while (it != _dlib.end()) {
		wdllname = it->dll.GetBuffer();
		wprocname = it->proc.GetBuffer();
		wcstombs(dllname, wdllname, MAX_MESSAGE_SIZE);
		wcstombs(procname, wprocname, MAX_MESSAGE_SIZE);
		_att.AddDll(dllname, (it->use_proc ? procname : NULL), (it->use_proc && it->chk_retn ? true : false));
		it++;
	}
	delete[] dllname;
	delete[] procname;

	textApp.GetWindowTextW(str);
	if (_att.IsAttached() && !_att.DetachShell()) {
		MessageBoxA(0, "Error, can't detach!", MSGBOX_TITLE, MB_ICONWARNING);
		_att.ClosePE();
		RestoreBackup();
	} else {
		if (!_att.AttachShell()) {
			MessageBoxA(0, "Error, can't attach!", MSGBOX_TITLE, MB_ICONWARNING);
			_att.ClosePE();
			RestoreBackup();
		} else {
			MessageBoxA(0, "Attaching successful!", MSGBOX_TITLE, MB_ICONINFORMATION);
		}
	}
	OpenAppFile(str.GetBuffer());
}
