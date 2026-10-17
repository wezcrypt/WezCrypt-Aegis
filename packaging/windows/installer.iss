; WezCrypt Aegis - Inno Setup script.
; Build: ISCC /DSourceDir=<staged dir> /DAppVersion=1.0.0 installer.iss

#ifndef SourceDir
  #error SourceDir must be defined
#endif
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6F2B8E61-6A0C-4E1B-9C1D-2B7E4A5AE915}
AppName=WezCrypt Aegis
AppVersion={#AppVersion}
AppVerName=WezCrypt Aegis {#AppVersion}
AppPublisher=WezCrypt
DefaultDirName={autopf}\WezCrypt Aegis
DefaultGroupName=WezCrypt Aegis
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
SetupIconFile=..\..\assets\branding\aegis.ico
UninstallDisplayIcon={app}\WezCryptAegis.exe
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
LicenseFile=..\..\LICENSES\LICENSE-WezCrypt-Aegis.txt
OutputBaseFilename=WezCryptAegis-{#AppVersion}-setup

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "Setup-Portable.cmd"

[Icons]
Name: "{group}\WezCrypt Aegis"; Filename: "{app}\WezCryptAegis.exe"
Name: "{group}\WezCrypt Aegis (Private Window)"; Filename: "{app}\WezCryptAegis.exe"; Parameters: "--private"
Name: "{autodesktop}\WezCrypt Aegis"; Filename: "{app}\WezCryptAegis.exe"; Tasks: desktopicon

[Run]
; Low-privilege AppContainer access required by the Chromium sandbox.
Filename: "{sys}\icacls.exe"; Parameters: """{app}"" /grant *S-1-15-2-2:(OI)(CI)(RX)"; Flags: runhidden waituntilterminated
Filename: "{app}\WezCryptAegis.exe"; Description: "{cm:LaunchProgram,WezCrypt Aegis}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: files; Name: "{app}\debug.log"
