[Components]
  # Append these lines to the [Components] section of MdeModulePkg.dsc.
  # 15_deploy_uefi_apps.sh inserts them automatically when they are absent.
  MdeModulePkg/Application/SecureManagerApp/SecureManagerApp.inf
  MdeModulePkg/Application/SignatureParserApp/SignatureParserApp.inf
