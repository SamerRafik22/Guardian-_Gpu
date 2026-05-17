"""
whitelist_system.py — Pre-seeded system process whitelist for Guardian
========================================================================
Contains the comprehensive set of known-safe Windows system processes,
Microsoft built-in apps, and common GPU driver processes.

Lookup is O(1) — no performance cost regardless of list size.
All comparisons use lowercase basename only (not full path).

Design: "unknown name at safe path" = KB candidate for learning
        "unknown name at suspicious path" = still detected
"""

# ── Complete Windows System Whitelist ──────────────────────────────────────────
SYSTEM_WHITELIST: set[str] = {

    # ─── Windows Kernel & Boot ────────────────────────────────────────────────
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "lsaiso.exe", "winlogon.exe",
    "ntoskrnl.exe", "hal.dll",

    # ─── Windows Shell & Desktop ──────────────────────────────────────────────
    "explorer.exe", "dwm.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "searchhost.exe", "searchapp.exe",
    "searchindexer.exe", "searchfilterhost.exe", "searchprotocolhost.exe",
    "textinputhost.exe", "lockapp.exe", "sihost.exe", "taskhostw.exe",
    "fontdrvhost.exe", "applicationframehost.exe",

    # ─── Core Windows Services ────────────────────────────────────────────────
    "svchost.exe", "spoolsv.exe", "conhost.exe", "condrv.sys",
    "runtimebroker.exe", "dllhost.exe", "wuauclt.exe", "wmiprvse.exe",
    "wmiapsrv.exe", "wbengine.exe", "audiodg.exe", "ctfmon.exe",
    "werfault.exe", "werfaultsecure.exe", "weretw.exe",
    "taskhostw.exe", "rdpclip.exe", "userinit.exe",
    "backgroundtaskhost.exe", "browser_broker.exe",
    "settingsynchost.exe", "userooberoker.exe",
    "presentationfontcache.exe", "printfilterpipelinesvc.exe",
    "wlanext.exe", "wpcmon.exe", "dfrgui.exe", "cleanmgr.exe",
    "msiexec.exe", "trustedinstaller.exe", "tiworker.exe",

    # ─── Windows Security & Defender ──────────────────────────────────────────
    "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe",
    "securityhealthsystray.exe", "securityhealthhost.exe",
    "mrt.exe", "msseces.exe", "antimalware service executable",
    "smartscreen.exe", "wdfilter.sys",

    # ─── Windows Update ────────────────────────────────────────────────────────
    "wuauclt.exe", "windowsupdatebox.exe", "musnotification.exe",
    "musnotificationux.exe", "usoclient.exe", "usocoreworker.exe",
    "updateassistant.exe", "windowsupdate.exe",

    # ─── Windows Built-in Apps ─────────────────────────────────────────────────
    "snippingtool.exe", "screenclippinghost.exe", "screensketch.exe",
    "mspaint.exe", "notepad.exe", "calc.exe", "charmap.exe",
    "magnify.exe", "narrator.exe", "osk.exe",
    "taskmgr.exe", "resmon.exe", "perfmon.exe",
    "mmc.exe", "regedit.exe", "regedt32.exe",
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "windowsterminal.exe", "wt.exe",
    "msconfig.exe", "dxdiag.exe", "winver.exe",
    "systemsettings.exe", "gpedit.msc", "secpol.msc",
    "eventvwr.exe", "devmgmt.msc", "diskmgmt.exe",
    "compmgmt.exe", "compmgmtlauncher.exe",
    "dfrgui.exe", "mdsched.exe", "rstrui.exe",
    "hdwwiz.exe", "netplwiz.exe",
    "printmanagement.msc", "wf.msc",
    "shrpubw.exe", "fsmgmt.msc",
    "fodhelper.exe", "credentialuibroker.exe",
    "credwiz.exe", "dpapimig.exe",
    "xpsrchvw.exe", "wordpad.exe",
    "write.exe", "wmplayer.exe",
    "video.ui.exe", "photos.exe", "microsoft.photos.exe",
    "hxmail.exe", "hxoutlook.exe", "hxtsr.exe", "hxcalendarappimm.exe",
    "windowsstore.dll", "winstore.app.exe",
    "musicapp.exe", "groove.exe", "zune.exe",
    "maps.exe", "bingmaps.exe", "mapsbroker.exe",
    "solitairely.exe", "solitaire.exe",
    "widgets.exe", "widgetservice.exe",
    "copilot.exe",

    # ─── Microsoft Edge ────────────────────────────────────────────────────────
    "msedge.exe", "msedgewebview2.exe", "microsoftedge.exe",
    "microsoftedgecp.exe", "microsoftedgesh.exe",
    "microsoftedgeupdate.exe", "edgeupdate.exe", "edgeupdatem.exe",
    "identity_helper.exe",

    # ─── Microsoft Office ──────────────────────────────────────────────────────
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "msaccess.exe", "mspub.exe", "infopath.exe",
    "lync.exe", "communicator.exe", "groove.exe",
    "officebackgroundtaskhandler.exe", "officeclicktorun.exe",
    "officec2rclient.exe", "integrator.exe",
    "msoia.exe", "firstrun.exe",

    # ─── Microsoft Teams & Communication ──────────────────────────────────────
    "teams.exe", "ms-teams.exe", "teamsupdatedaemon.exe",
    "skype.exe", "skypehost.exe", "skypefordesktop.exe",

    # ─── OneDrive & Sync ───────────────────────────────────────────────────────
    "onedrive.exe", "microsoftonedrivesync.exe", "onedriveupdater.exe",
    "onedrivestandaloneudater.exe", "filesyncconfig.exe",
    "filecoauth.exe", "odopen.exe",

    # ─── Windows Phone/Mobile ─────────────────────────────────────────────────
    "phoneexperiencehost.exe", "yourphone.exe", "yourphoneappproxy.exe",
    "yourphoneserver.exe", "phonexperiencehost.exe",

    # ─── Xbox / Gaming Services ────────────────────────────────────────────────
    "gamebar.exe", "gamebarpresencewriter.exe", "gamebarft.exe",
    "xboxapp.exe", "xboxgamingoverlay.exe", "xboxpcapp.exe",
    "gamingtcui.exe", "xgameruntime.dll",

    # ─── Input / Tablet / Touch ────────────────────────────────────────────────
    "tabtip.exe", "tabtip32.exe", "inputapp.exe", "tabsvc.dll",
    "touchkeyboard.exe", "penservice.exe",

    # ─── Windows Accessibility ─────────────────────────────────────────────────
    "narrator.exe", "magnify.exe", "osk.exe", "utilman.exe",
    "stikypad.exe", "stikynot.exe",

    # ─── Windows Networking ────────────────────────────────────────────────────
    "dnscache.exe", "netsh.exe", "ipconfig.exe", "ping.exe",
    "tracert.exe", "nslookup.exe", "net.exe", "net1.exe",
    "vpnclient.exe", "rasphone.exe", "rasdial.exe",
    "mobilityextension.exe",

    # ─── Windows Display & Monitor Management ─────────────────────────────────
    "dwm.exe", "dccw.exe", "displayswitch.exe",
    "customdpi.exe", "colorcpl.exe", "hdr.exe",
    "msdtc.exe", "multimon.exe",

    # ─── Development Tools (Microsoft built-in) ────────────────────────────────
    "devhome.exe", "winget.exe", "wsl.exe", "wslhost.exe",
    "bash.exe", "ubuntu.exe", "kali.exe",

    # ─── NVIDIA GPU Drivers & Tools ────────────────────────────────────────────
    "nvcontainer.exe", "nvdisplay.container.exe", "nvtelemetry.exe",
    "nvidia overlay.exe", "nvoaWrappercache.exe",
    "nvvsvc.exe", "nvwmi64.exe", "nvxdsync.exe",
    "nv_hostengine.exe", "nvsmartmaxapp.exe",
    "shadowplay.exe", "geforceexperience.exe",
    "nvcplui.exe",  # Control Panel

    # ─── AMD GPU Drivers & Tools ───────────────────────────────────────────────
    "radeonSettings.exe", "radeonsoftware.exe", "amdow.exe",
    "amdrsserv.exe", "cncserver.exe", "amdfenddr.exe",
    "amdarsdrv.exe",

    # ─── Intel GPU Drivers & Tools ─────────────────────────────────────────────
    "igcc.exe", "igfxem.exe", "igfxhk.exe", "igfxtray.exe",
    "intelcphs.exe", "intelhidsvc.exe",

    # ─── Common System Utilities ───────────────────────────────────────────────
    "xcopy.exe", "robocopy.exe", "sc.exe", "regsvr32.exe",
    "rundll32.exe", "regasm.exe", "installutil.exe",
    "cscript.exe", "wscript.exe", "mshta.exe",
    "ie4uinit.exe", "inetinfo.exe",
    "fsutil.exe", "diskpart.exe", "chkdsk.exe",
    "cipher.exe", "icacls.exe", "takeown.exe",
    "compact.exe", "convert.exe", "expand.exe",
    "forfiles.exe", "gpupdate.exe", "gpresult.exe",
    "auditpol.exe", "bcdedit.exe", "bitsadmin.exe",
    "certutil.exe",

    # ─── Guardian itself ───────────────────────────────────────────────────────
    "guardian_live.py", "guardian_brain.py", "python.exe", "python3.exe",
    "pythonw.exe", "py.exe",
}

# Lowercase cache for faster lookup
_WHITELIST_LOWER: set[str] = {name.lower() for name in SYSTEM_WHITELIST}


def is_system_whitelisted(process_name: str) -> bool:
    """
    Check if a process name is in the system whitelist.
    Accepts full paths — verifies path if provided, else falls back to basename.
    Case-insensitive.
    """
    if not process_name:
        return False
    
    proc_lower = process_name.replace('\\', '/').lower().strip()
    basename = proc_lower.split('/')[-1]
    
    # Security: If a full path is provided, ensure it comes from a safe Windows directory
    if '/' in proc_lower:
        if not ("windows/system32" in proc_lower or 
                "windows/systemapps" in proc_lower or 
                "program files" in proc_lower or 
                "windows/explorer.exe" in proc_lower):
            return False

    return basename in _WHITELIST_LOWER
