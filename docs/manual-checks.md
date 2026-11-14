# Manual checks for the installers

CI installs silently and never clicks a dialog (docs/packaging.md). Run these once on a real
machine per release that changes an installer. Use a throwaway machine or VM; the unsigned
packages are expected to warn.

## Windows (interactive MSI)

Use a standard (non-administrator) user whose name you know, on a machine with an administrator
account to elevate with. Get the MSI from the release.

1. Double-click the MSI. Expect: SmartScreen "Windows protected your PC" (unsigned); *More info*,
   *Run anyway*. Then the UAC prompt asks for administrator credentials.
2. Welcome, licence, folder, then the page **Who may use SocketGuard**. Expect: the box is ticked
   and reads "Let *your account* manage SocketGuard without administrator rights" with **your
   own signed-in account** (not the administrator you elevated with). On a domain account the
   text shows `DOMAIN\user`; on a local one just the name.
3. Back and Next: Back from this page returns to the folder page, Next goes to "Ready to install",
   and Back from there returns to this page. Untick the box, go Next, Back: it is still unticked.
4. If the WebView2 runtime is not installed (check Apps & features for "Microsoft Edge WebView2
   Runtime"), the page shows a note with the download link; if it is installed the area is empty.
5. Install. Expect: no error; a progress line mentions registering the service.
6. Check from a normal (non-elevated) prompt: `sc query SocketGuard` shows RUNNING.
   `net localgroup "SocketGuard Users"` lists your account (only if the box was ticked).
7. **Sign out and in again**, then open **SocketGuard** from the Start menu. Expect: the window
   opens with no elevation prompt and no connection banner (no "service is not installed", "stopped"
   or "this account may not use it" message); `socketguard status` works in a new normal terminal
   (the install folder is on PATH).
8. Run the next MSI over it (double-click). Expect: no "uninstall first" message, the service
   keeps running afterwards (new process), your settings are still listed, one SocketGuard entry in
   Apps & features with the new version.
9. Settings, Apps, Installed apps, SocketGuard, Uninstall. Expect: it completes; `sc query
   SocketGuard` says the service does not exist; `C:\ProgramData\SocketGuard` still exists
   (settings and keys are kept).
10. Purge, from an elevated terminal, with a copy of the daemon (it is gone after step 9; keep a
    copy from step 7, or install again and purge first, see "Uninstall and purge" in the README):
    `socketguard-daemon uninstall --purge --yes`. Expect: it ends with "SocketGuard is uninstalled."
    and `C:\ProgramData\SocketGuard` is gone.

## Windows (portable zip)

CI drives the portable daemon through the CLI and never opens the window.

1. Unzip, start `socketguard-ui.exe`, press **Start** and accept the administrator prompt.
   Expect: the app list fills in.
2. Start a program that listens on a port. Expect: it appears in Apps within a few seconds,
   without clicking anything (the window receives the daemon's events).
3. Close the window with the X. Expect: "Removing rules…", then the window closes; no
   `socketguard-daemon.exe` is left in Task Manager and `data\last-exit.log` says "clean".
4. Start it again, then end `socketguard-daemon.exe` in Task Manager and close the window.
   Expect: it closes within a few seconds.

## macOS (unsigned pkg)

1. Download the pkg in a browser (so it is quarantined) and double-click it. Expect: "cannot be
   opened because it is from an unidentified developer" (or "Apple could not verify..."). Then
   either right-click, *Open*, *Open*; or *System Settings, Privacy & Security, Open Anyway* and
   authenticate.
2. Click through the installer and authenticate. Expect: "The installation was successful".
3. In Terminal: `sudo launchctl print system/de.lhns.socketguard` shows the job; `sudo socketguard
   status` answers.
4. Open **SocketGuard** from /Applications. Expect: Gatekeeper may ask once to confirm (right-click,
   *Open*); the window opens and, as your account is not allowed yet, says "The service is running,
   but this account may not use it." with an **Allow my account** button.
5. Run `sudo socketguard-daemon access allow $USER` (or use that button), sign out and in; the app
   then opens with no banner and works without `sudo`.
6. In the app: Settings, **Remove SocketGuard...**, leave "Also delete settings and keys?" unticked,
   press **Remove SocketGuard**, authenticate. Expect: the app says "SocketGuard is removed" and `sudo launchctl print system/de.lhns.socketguard` fails;
   the app, the programs in /Library/Application Support/SocketGuard and the link in /usr/local/bin remain (a pkg cannot delete them): delete them as in the
   README, then `sudo pkgutil --forget de.lhns.socketguard`.
7. Install again and use **Remove SocketGuard...** with "Also delete settings and keys?" ticked. Expect:
   the data in `/Library/Application Support/SocketGuard` is gone (the programs stay) and `/etc/pf.conf` has no `socketguard`
   anchor line.
