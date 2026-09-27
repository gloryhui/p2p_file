# 应用图标

来源：用户提供的猫咪、地球和双向箭头插画，经内置 imagegen 编辑外侧透明背景。
选用的处理提示：保留猫咪、蓝色圆角背景、地球轨道与围巾箭头；仅移除外侧白底，保持居中及安全留白。

- `app-icon.png`：1024 × 1024 图标母版。
- `app-icon-ui.png`：256 × 256，编译进程序，供主页与设置页共用。
- `app-icon.icns`：macOS 多分辨率图标，打包时写入应用 Resources 和 Info.plist。
- `app-icon.ico`：Windows 16、24、32、48、64、128、256 像素图标。
- `app-icon.rc`：Windows 可执行文件及窗口使用的图标资源（ID 1）。

修改母版后，在 macOS 仓库根目录运行 `python3 scripts/generate-app-icons.py`，
使用系统 sips 和 iconutil 重新生成全部尺寸与容器；构建机器无需重新生成图标。

系统应用图标在重新构建、打包后生效；已有的应用包不会自动更新。
