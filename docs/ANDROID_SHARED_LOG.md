# Android shared-storage log

The Android host redirects both stdout and stderr to an append-only log in shared
storage through the Storage Access Framework (SAF).

For Sekhmet, the game profile has `data_application = "Sekhmet"`, so the
requested destination is:

```text
/sdcard/sekhmet/log.txt
```

Android 11 and later restrict direct filesystem access to arbitrary shared
storage paths. The activity therefore asks the user to select the
`sekhmet` directory through `ACTION_OPEN_DOCUMENT_TREE`. It validates that
the returned tree document ID is `primary:sekhmet`, persists the write grant
with `takePersistableUriPermission`, and remembers the URI in app preferences.
The native host opens or creates `log.txt` in append mode and redirects both
C standard streams to its file descriptor.

The SAF permission is separate from the game installation folder and the
`ms0:/PSP/` virtual filesystem. No broad `MANAGE_EXTERNAL_STORAGE`
permission is requested.

If the player cancels the picker, the provider does not support append mode,
or SAF access fails, the host falls back to the existing app-private log so
diagnostics are not lost. The private fallback remains accessible to debug
builds with `adb shell run-as`.

The Android picker and provider behavior still need validation on a physical
Android 11+ device. In particular, verify that the selected folder is
`/sdcard/sekhmet`, that `log.txt` is appended across launches, and that
the persisted grant survives a reboot.
