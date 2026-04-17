# IDASlicer

IDASlicer 是一个 IDA Pro 的生产力插件，旨在帮助逆向工程师将二进制文件的特定部分（函数、段或任意选择的内容）提取、管理并“切片”到新的 IDA 数据库或原始二进制文件中，特别适用于分析大型文件。

[English Version](./README.md)

## 功能特点

- **多源切片**：通过右键上下文菜单直接从反汇编视图添加条目到切片列表：
  - **Add function to slicer**：自动检测当前函数边界。
  - **Add selection to slicer**：使用您当前的手动高亮/选择内容。
  - **Add current segment to slicer**：抓取包含光标的整个段。
- **切片管理**：专用的 UI 面板，在处理前检查、编辑（名称、范围、权限等）或删除条目。
- **数据库切片 (IDA 9.1+)**：
  - 创建一个全新的 IDA 数据库 (`.i64`)，仅包含所选的切片。
  - 自动检测文件类型（ELF、PE、Mach-O）和架构（x86、x64、ARM、ARM64）以使用适当的模板。
  - 使用 IDA Domain API 进行无头（headless）数据库生成。
- **原始二进制导出**：
  - 将所有切片导出为单独的原始二进制文件。
  - 文件名自动格式化为 `Name_StartAddr_EndAddr.seg`。
  - 文件直接保存到当前分析文件所在的目录。

## 要求

- **IDA Pro 9.1+**：“Slice and Create IDA Database”功能需要（需要 `ida_domain` API）。
- **Python 3**：插件在 IDA 集成的 Python 环境中运行。
- **PySide6**：现代 IDA Pro 安装中已包含。

## 安装

将整个文件夹复制到您的 IDA 插件目录中：
- **Windows**: `%AppData%\Hex-Rays\IDA Pro\plugins`
- **Linux/macOS**: `~/.idapro/plugins`

## 使用方法

1. **填充列表**：
   - 在 **IDA View (反汇编视图)** 中右键单击。
   - 导航到 `Add to Slicer /`。
   - 选择添加函数、选择内容或整个段。
2. **打开插件**：
   - 前往 `Edit -> Plugins -> IDASlicer`。
3. **检查与编辑**：
   - 双击表格中的条目以修改其属性。
   - 右键单击条目以将其删除。
4. **导出**：
   - **Slice and Create IDA Database**：生成一个新的 `.i64` 文件，重新创建段并填充数据。
   - **Save segments to .seg files**：将每个条目的原始字节转储到当前工作区中的 `.seg` 文件中。

## 工作原理

### 数据库切片
该插件采用基于模板的方法。它从 `obj_minis` 目录复制一个“迷你”数据库，然后使用 IDA 的 `ida_domain` API 运行后台 Python 进程，将选定的段及其内容注入到新数据库中，而无需关闭您当前的会话。

### 原始导出
它利用 `ida_bytes.get_bytes` 读取数据库内容并直接写入磁盘，确保您当前 IDB 中的任何手动修补或重新分析的数据都能在导出中得到保留。

## 许可证
[MIT](LICENSE)
