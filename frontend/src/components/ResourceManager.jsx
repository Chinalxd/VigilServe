import { useState, useEffect, useRef } from 'react'
import './ResourceManager.css'
import { copyFiles, deleteFiles, createFolder, renameFile, readTextFile, writeTextFile, createFile, zipFiles, unzipFile } from '../services/api'
import { authHeaders } from '../services/auth'
import { usePerm } from '../services/permissions'
import Icon from './AppIcon'

const API_BASE = '/api'

function fmtSize(bytes) {
  if (bytes === 0) return '-'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0, size = bytes
  while (size >= 1024 && i < units.length - 1) { size /= 1024; i++ }
  return `${size.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

// 允许在线编辑的纯文本扩展名（2MB 上限由后端强制）
const EDITABLE_EXTS = new Set([
  'txt', 'log', 'ini', 'conf', 'cfg', 'json', 'xml', 'yml', 'yaml', 'md',
  'py', 'js', 'jsx', 'ts', 'tsx', 'css', 'scss', 'less', 'html', 'htm',
  'bat', 'cmd', 'ps1', 'sh', 'sql', 'csv', 'env', 'toml', 'properties', 'reg',
])

const isEditableFile = (name) => {
  const m = String(name).toLowerCase().match(/\.([a-z0-9]+)$/)
  return !!m && EDITABLE_EXTS.has(m[1])
}

export default function ResourceManager({ serverId }) {
  // R-13：资源管理按**具体操作**授权。这里只做显示层控制（菜单项显隐），
  const { can } = usePerm()
  const canRes = (op) => can('host', 'resources', 'view', op)
  const [drives, setDrives] = useState([])
  const [items, setItems] = useState([])
  const [currentPath, setCurrentPath] = useState('')
  const [parentPath, setParentPath] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [sortKey, setSortKey] = useState('name')
  const [sortAsc, setSortAsc] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [selected, setSelected] = useState(new Set())
  const [clipboard, setClipboard] = useState([])
  const [clipboardSourcePath, setClipboardSourcePath] = useState('')
  const [targetDrive, setTargetDrive] = useState('')
  const [contextMenu, setContextMenu] = useState(null)
  const [editingItem, setEditingItem] = useState(null)
  const [editValue, setEditValue] = useState('')
  const [editor, setEditor] = useState(null)
  const [editorValue, setEditorValue] = useState('')
  const [status, setStatus] = useState({ text: '', type: 'idle' })
  const PAGE_SIZE = 200
  const uploadRef = useRef(null)
  const listBodyRef = useRef(null)
  const editInputRef = useRef(null)
  const menuRef = useRef(null)
  const pastePollRef = useRef(null)

  useEffect(() => {
    loadDrives()
    return () => {
      if (pastePollRef.current) {
        clearInterval(pastePollRef.current)
        pastePollRef.current = null
      }
    }
  }, [serverId])

  useEffect(() => { setSelected(new Set()) }, [currentPath, page])

  useEffect(() => {
    if (status.type === 'success' || status.type === 'error') {
      const delay = status.type === 'error' ? 5000 : 3000
      const t = setTimeout(() => setStatus({ text: '', type: 'idle' }), delay)
      return () => clearTimeout(t)
    }
  }, [status])

  useEffect(() => {
    if (!contextMenu) return
    const onMouseDown = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setContextMenu(null)
      }
    }
    document.addEventListener('mousedown', onMouseDown)
    return () => document.removeEventListener('mousedown', onMouseDown)
  }, [contextMenu])

  // 右键菜单打开后，根据实际尺寸调整位置，防止超出视口
  useEffect(() => {
    if (!contextMenu || !menuRef.current) return
    const rect = menuRef.current.getBoundingClientRect()
    const padding = 8
    let x = contextMenu.x
    let y = contextMenu.y
    if (x + rect.width + padding > window.innerWidth) {
      x = window.innerWidth - rect.width - padding
    }
    if (y + rect.height + padding > window.innerHeight) {
      y = window.innerHeight - rect.height - padding
    }
    if (x < padding) x = padding
    if (y < padding) y = padding
    if (x !== contextMenu.x || y !== contextMenu.y) {
      setContextMenu(prev => prev ? { ...prev, x, y } : null)
    }
  }, [contextMenu])

  useEffect(() => {
    if (editingItem && editInputRef.current) {
      editInputRef.current.focus()
      editInputRef.current.select()
    }
  }, [editingItem])

  const loadDrives = async () => {
    setLoading(true)
    try {
      // 阶段3 给 file_explorer 全模块加了登录校验，这里必须带鉴权头，否则 401（列表空白）
      const res = await fetch(`${API_BASE}/servers/${serverId}/drives`, { headers: authHeaders() })
      const data = await res.json()
      setDrives(data.drives || [])
      setItems([])
      setCurrentPath('')
      setParentPath(null)
      setPage(1)
      setTotal(0)
      setTargetDrive('')
      setEditingItem(null)
    } catch (e) {
      setError('无法获取磁盘列表')
    }
    setLoading(false)
  }

  const browse = async (path, p = 1) => {
    setLoading(true)
    setError('')
    setEditingItem(null)
    try {
      const url = `${API_BASE}/servers/${serverId}/files?path=${encodeURIComponent(path)}&page=${p}&size=${PAGE_SIZE}`
      const res = await fetch(url, { headers: authHeaders() })
      if (!res.ok) throw new Error('访问失败')
      const data = await res.json()
      setItems(data.items || [])
      setCurrentPath(data.path || path)
      setParentPath(data.parent)
      setTotal(data.total || 0)
      setPage(data.page || 1)
    } catch (e) {
      setError(e.message)
    }
    setLoading(false)
  }

  const refreshCurrent = async (preservePlaceholders = false) => {
    if (!currentPath) return
    try {
      const url = `${API_BASE}/servers/${serverId}/files?path=${encodeURIComponent(currentPath)}&page=${page}&size=${PAGE_SIZE}`
      const res = await fetch(url, { headers: authHeaders() })
      if (!res.ok) throw new Error('访问失败')
      const data = await res.json()
      const fetched = data.items || []
      setItems(prev => {
        const placeholders = preservePlaceholders ? prev.filter(i => i.isPastePlaceholder) : []
        return mergePlaceholders(fetched, placeholders)
      })
      setTotal(data.total || 0)
      setPage(data.page || 1)
    } catch (e) {
    }
  }

  const mergePlaceholders = (fetched, placeholders) => {
    const names = new Set(fetched.map(i => i.name))
    const kept = placeholders.filter(p => !names.has(p.name))
    return [...kept, ...fetched]
  }

  const goHome = () => loadDrives()
  const handleBack = async () => {
    if (parentPath && parentPath !== currentPath) browse(parentPath)
    else loadDrives()
  }
  const isAtRoot = !parentPath || parentPath === currentPath

  const joinPath = (dir, name) => {
    if (!dir) return name
    const sep = dir.includes('\\') ? '\\' : '/'
    return dir.replace(/[\\/]+$/, '') + sep + name
  }

  // `window.open` 带不了 Authorization 头，而下载端点在安全加固后要求登录 →
  // 改成 fetch 取 blob 再本地另存（不把 token 拼进 URL，免得落进访问日志）。
  const saveBlob = async (url, fallbackName) => {
    setStatus({ text: '正在准备下载…', type: 'loading' })
    setError('')
    try {
      const res = await fetch(url, { headers: authHeaders() })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const blob = await res.blob()
      let name = fallbackName
      const cd = res.headers.get('Content-Disposition') || ''
      const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(cd)
      if (m && m[1]) {
        try { name = decodeURIComponent(m[1]) } catch { name = m[1] }
      }
      const a = document.createElement('a')
      const objUrl = URL.createObjectURL(blob)
      a.href = objUrl
      a.download = name
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(objUrl), 5000)
      setStatus({ text: '下载已开始', type: 'success' })
    } catch (e) {
      setError(`下载失败：${e.message}`)
      setStatus({ text: `下载失败：${e.message}`, type: 'error' })
    }
  }

  const downloadOne = (fullPath) => {
    const url = `${API_BASE}/servers/${serverId}/files/download?path=${encodeURIComponent(fullPath)}`
    const name = String(fullPath).split(/[\\/]/).filter(Boolean).pop() || 'download'
    saveBlob(url, name)
  }

  const downloadSelected = () => {
    if (selected.size === 0) return
    const paths = Array.from(selected).map(name => joinPath(currentPath, name))
    const url = `${API_BASE}/servers/${serverId}/files/download-multi?paths=${encodeURIComponent(paths.join('|'))}`
    const base = String(currentPath).split(/[\\/]/).filter(Boolean).pop() || 'files'
    saveBlob(url, `${base}.zip`)
  }

  const selectedPaths = () => Array.from(selected).map(name => joinPath(currentPath, name))

  const toggleSelect = (name, append = false) => {
    if (editingItem) return
    setSelected(prev => {
      if (append) {
        const next = new Set(prev)
        if (next.has(name)) next.delete(name); else next.add(name)
        return next
      }
      return new Set([name])
    })
  }

  const generateNewFolderName = () => {
    const base = '新建文件夹'
    const names = new Set(items.map(i => i.name))
    if (!names.has(base)) return base
    let i = 1
    while (names.has(`${base}${i}`)) i++
    return `${base}${i}`
  }

  const generateNewFileName = () => {
    const base = '新建文件.txt'
    const names = new Set(items.map(i => i.name))
    if (!names.has(base)) return base
    const stem = base.slice(0, -4)
    const ext = '.txt'
    let i = 1
    while (names.has(`${stem}${i}${ext}`)) i++
    return `${stem}${i}${ext}`
  }

  const handleCreateFile = () => {
    if (!currentPath || editingItem) return
    const name = generateNewFileName()
    const virtualItem = { name, is_dir: false, size: 0, mtime: '', ext: 'txt', isVirtual: true }
    setItems(prev => [virtualItem, ...prev])
    setSelected(new Set())
    setEditingItem({ name, originalName: name, isNew: true, isFile: true })
    setEditValue(name)
  }

  const handleCreateFolder = () => {
    if (!currentPath || editingItem) return
    const name = generateNewFolderName()
    const virtualItem = { name, is_dir: true, size: 0, mtime: '', ext: '', isVirtual: true }
    setItems(prev => [virtualItem, ...prev])
    setSelected(new Set())
    setEditingItem({ name, originalName: name, isNew: true })
    setEditValue(name)
  }

  const handleRename = () => {
    if (selected.size !== 1 || !currentPath || editingItem) return
    const name = Array.from(selected)[0]
    setEditingItem({ name, originalName: name, isNew: false })
    setEditValue(name)
  }

  const cancelEdit = () => {
    if (!editingItem) return
    if (editingItem.isNew) {
      setItems(prev => prev.filter(i => !i.isVirtual))
    }
    setEditingItem(null)
    setEditValue('')
  }

  const commitEdit = async (finalName) => {
    if (!editingItem) return
    const trimmed = finalName.trim()
    if (!trimmed || trimmed === editingItem.originalName) {
      cancelEdit()
      return
    }
    const oldName = editingItem.originalName
    const isNew = editingItem.isNew
    const isFile = !!editingItem.isFile

    setEditingItem(null)
    setEditValue('')
    setError('')
    setStatus({ text: isNew ? (isFile ? `正在创建文件 "${trimmed}"...` : `正在创建文件夹 "${trimmed}"...`) : '正在重命名...', type: 'loading' })

    if (isNew) {
      setItems(prev => prev.map(i =>
        i.name === oldName && i.isVirtual
          ? { name: trimmed, is_dir: !isFile, size: 0, mtime: '刚刚', ext: '', isPending: true }
          : i
      ))
    } else {
      setItems(prev => prev.map(i => i.name === oldName ? { ...i, name: trimmed, isPending: true } : i))
      // 同步更新 selected，避免重命名后右键菜单丢失重命名项
      setSelected(prev => {
        if (!prev.has(oldName)) return prev
        const next = new Set(prev)
        next.delete(oldName)
        next.add(trimmed)
        return next
      })
    }

    try {
      if (isNew) {
        const target = joinPath(currentPath, trimmed)
        if (isFile) await createFile(serverId, target)
        else await createFolder(serverId, target)
      } else {
        const source = joinPath(currentPath, oldName)
        const target = joinPath(currentPath, trimmed)
        await renameFile(serverId, source, target)
      }
      setItems(prev => prev.map(i => i.name === trimmed ? { ...i, isPending: false } : i))
      setStatus({ text: isNew ? (isFile ? `文件 "${trimmed}" 创建成功` : `文件夹 "${trimmed}" 创建成功`) : '重命名成功', type: 'success' })
    } catch (e) {
      setError(`${isNew ? (isFile ? '新建文件' : '新建文件夹') : '重命名'}失败：${e.message || '未知错误'}`)
      setStatus({ text: `${isNew ? (isFile ? '新建文件' : '新建文件夹') : '重命名'}失败：${e.message || '未知错误'}`, type: 'error' })
      if (isNew) {
        setItems(prev => prev.filter(i => !(i.name === trimmed && (i.isVirtual || i.isPending))))
      } else {
        setItems(prev => prev.map(i => i.name === trimmed ? { ...i, name: oldName, isPending: false } : i))
        setSelected(prev => {
          if (!prev.has(trimmed)) return prev
          const next = new Set(prev)
          next.delete(trimmed)
          next.add(oldName)
          return next
        })
      }
    }
  }

  const handleEditKeyDown = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      commitEdit(e.target.value)
    } else if (e.key === 'Escape') {
      cancelEdit()
    }
  }

  const handleEditBlur = (e) => {
    commitEdit(e.target.value)
  }

  const handleUpload = async (e) => {
    const file = e.target.files?.[0]
    if (!file || !currentPath) return
    const tempItem = {
      name: file.name,
      is_dir: false,
      size: file.size,
      mtime: '上传中...',
      ext: '',
      isPending: true,
    }
    setItems(prev => [tempItem, ...prev])
    setError('')
    setStatus({ text: `正在上传 "${file.name}"...`, type: 'loading' })
    try {
      const form = new FormData()
      form.append('file', file)
      const res = await fetch(
        `${API_BASE}/servers/${serverId}/files/upload?path=${encodeURIComponent(currentPath)}`,
        { method: 'POST', body: form, headers: authHeaders() }
      )
      if (!res.ok) throw new Error('上传失败')
      await browse(currentPath, page)
      setStatus({ text: `"${file.name}" 上传成功`, type: 'success' })
    } catch (e) {
      setError(e.message || '上传失败')
      setStatus({ text: `上传失败：${e.message || '未知错误'}`, type: 'error' })
      setItems(prev => prev.filter(i => !(i.isPending && i.name === file.name)))
    }
    e.target.value = ''
  }

  const handleCopy = () => {
    if (selected.size === 0 || editingItem) return
    setClipboard(selectedPaths())
    setClipboardSourcePath(currentPath)
    setStatus({ text: `已复制 ${selected.size} 项`, type: 'success' })
  }

  const handlePaste = async (targetPath) => {
    if (editingItem) return
    const pasteTarget = targetPath || currentPath
    if (clipboard.length === 0 || !pasteTarget) return
    setError('')

    const sourceNames = clipboard.map(src => {
      const s = src.replace(/\\/g, '/')
      return s.substring(s.lastIndexOf('/') + 1) || src
    })

    const placeholders = sourceNames.map(name => ({
      name,
      is_dir: false,
      size: 0,
      mtime: '粘贴中...',
      ext: '',
      isPending: true,
      isPastePlaceholder: true,
    }))
    setItems(prev => [...placeholders, ...prev])
    setStatus({ text: `正在粘贴 ${sourceNames.length} 项...`, type: 'loading' })

    // 后台轮询目录，复制过程中即可看到新文件出现
    if (pastePollRef.current) clearInterval(pastePollRef.current)
    pastePollRef.current = setInterval(() => {
      refreshCurrent(true)
    }, 2000)

    try {
      await copyFiles(serverId, clipboard, pasteTarget)
      if (pastePollRef.current) {
        clearInterval(pastePollRef.current)
        pastePollRef.current = null
      }
      setClipboard([])
      setClipboardSourcePath('')
      setTargetDrive('')
      await refreshCurrent(false)
      setStatus({ text: `粘贴完成：${sourceNames.length} 项`, type: 'success' })
    } catch (e) {
      if (pastePollRef.current) {
        clearInterval(pastePollRef.current)
        pastePollRef.current = null
      }
      setError(e.message || '粘贴失败')
      setStatus({ text: `粘贴失败：${e.message || '未知错误'}`, type: 'error' })
      setItems(prev => prev.filter(i => !i.isPastePlaceholder))
    }
  }

  const handleDriveClick = (d) => {
    if (editingItem) return
    if (clipboard.length > 0) {
      if (targetDrive === d.path) {
        browse(d.path)
        setTargetDrive('')
      } else {
        setTargetDrive(d.path)
      }
    } else {
      browse(d.path)
    }
  }

  const handleDelete = async () => {
    if (selected.size === 0 || editingItem) return
    const names = Array.from(selected).join('\n')
    if (!window.confirm(`确定要删除以下 ${selected.size} 项吗？\n${names}`)) return
    const paths = selectedPaths()
    setItems(prev => prev.filter(i => !selected.has(i.name)))
    setSelected(new Set())
    setError('')
    setStatus({ text: `正在删除 ${paths.length} 项...`, type: 'loading' })
    try {
      await deleteFiles(serverId, paths)
      setStatus({ text: `删除完成：${paths.length} 项`, type: 'success' })
    } catch (e) {
      setError(e.message || '删除失败')
      setStatus({ text: `删除失败：${e.message || '未知错误'}`, type: 'error' })
      await browse(currentPath, page)
    }
  }

  const handleEditFile = async (name) => {
    if (!currentPath || editingItem) return
    const fullPath = joinPath(currentPath, name)
    setEditorValue('')
    setEditor({ path: fullPath, name, size: 0, loading: true, saving: false })
    try {
      const data = await readTextFile(serverId, fullPath)
      setEditor({ path: fullPath, name, size: data.size || 0, loading: false, saving: false })
      setEditorValue(data.content ?? '')
    } catch (e) {
      setEditor(null)
      setStatus({ text: `读取文件失败：${e.message || '未知错误'}`, type: 'error' })
    }
  }

  const closeEditor = () => setEditor(null)

  const handleSaveEditor = async () => {
    if (!editor || editor.loading || editor.saving) return
    setEditor(prev => ({ ...prev, saving: true }))
    try {
      await writeTextFile(serverId, editor.path, editorValue)
      setEditor(prev => ({ ...prev, saving: false }))
      setStatus({ text: `已保存 "${editor.name}"`, type: 'success' })
      refreshCurrent(false)
    } catch (e) {
      setEditor(prev => ({ ...prev, saving: false }))
      setStatus({ text: `保存失败：${e.message || '未知错误'}`, type: 'error' })
    }
  }

  const handleEditorKeyDown = (e) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S')) {
      e.preventDefault()
      handleSaveEditor()
    } else if (e.key === 'Escape') {
      e.preventDefault()
      closeEditor()
    }
  }

  const handleZip = async () => {
    if (selected.size === 0 || editingItem || !currentPath) return
    const paths = selectedPaths()
    setStatus({ text: `正在压缩 ${paths.length} 项...`, type: 'loading' })
    try {
      const res = await zipFiles(serverId, paths, currentPath, '')
      const zipName = (res.zip_path || '').split(/[\\/]/).pop() || '压缩包'
      setStatus({ text: `压缩完成：${res.count ?? paths.length} 个文件 → ${zipName}`, type: 'success' })
      await refreshCurrent(false)
    } catch (e) {
      setStatus({ text: `压缩失败：${e.message || '未知错误'}`, type: 'error' })
    }
  }

  const handleUnzip = async (name) => {
    if (!currentPath || editingItem) return
    const fullPath = joinPath(currentPath, name)
    setStatus({ text: `正在解压 "${name}"...`, type: 'loading' })
    try {
      const res = await unzipFile(serverId, fullPath)
      const destName = (res.dest || '').split(/[\\/]/).pop() || '同名文件夹'
      setStatus({ text: `解压完成 → ${destName}`, type: 'success' })
      await refreshCurrent(false)
    } catch (e) {
      setStatus({ text: `解压失败：${e.message || '未知错误'}`, type: 'error' })
    }
  }

  const handleRowClick = (e, item) => {
    if (editingItem) return
    if (e.ctrlKey || e.metaKey) {
      toggleSelect(item.name, true)
      return
    }
    toggleSelect(item.name, false)
  }

  const sort = (key) => {
    if (editingItem) return
    if (sortKey === key) setSortAsc(!sortAsc)
    else { setSortKey(key); setSortAsc(true) }
  }

  const sorted = [...items].sort((a, b) => {
    if (a.isVirtual && !b.isVirtual) return -1
    if (!a.isVirtual && b.isVirtual) return 1
    if (a.isPending && !b.isPending) return -1
    if (!a.isPending && b.isPending) return 1
    if (a.is_dir && !b.is_dir) return -1
    if (!a.is_dir && b.is_dir) return 1
    let va = a[sortKey], vb = b[sortKey]
    if (sortKey === 'size') { va = a.is_dir ? -1 : va; vb = b.is_dir ? -1 : vb }
    if (typeof va === 'string') return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va)
    return sortAsc ? va - vb : vb - va
  })

  const pasteTarget = currentPath || targetDrive
  const pasteHint = currentPath
    ? '粘贴到当前目录'
    : (targetDrive ? `粘贴到 ${targetDrive}` : '请先选择目标分区')

  const openContextMenu = (e, item) => {
    e.preventDefault()
    e.stopPropagation()
    if (editingItem) return
    // 右键某一项时，若该项未被选中则仅选中该项；若已在选中集合中则保持当前多选
    let newSelected = selected
    if (item) {
      newSelected = selected.has(item.name) ? selected : new Set([item.name])
      if (newSelected !== selected) setSelected(newSelected)
    }
    const estimatedItems = buildMenuItems(newSelected, clipboard, pasteTarget, currentPath)
    const menuHeight = estimatedItems.length * 36 + 12
    const menuWidth = 150
    const padding = 8
    let x = e.clientX
    let y = e.clientY
    if (x + menuWidth + padding > window.innerWidth) {
      x = window.innerWidth - menuWidth - padding
    }
    if (y + menuHeight + padding > window.innerHeight) {
      y = window.innerHeight - menuHeight - padding
    }
    if (x < padding) x = padding
    if (y < padding) y = padding
    setContextMenu({ x, y, item: item || null })
  }

  const buildMenuItems = (sel, clip, target, path) => {
    const menu = []
    // 找到选中项对应的完整信息（判断文件/目录、扩展名）
    const selNames = Array.from(sel)
    const selItems = selNames.map(n => items.find(i => i.name === n)).filter(Boolean)
    const singleFile = sel.size === 1 && selItems.length === 1 && !selItems[0].is_dir
      ? selItems[0] : null
    // R-13：每一项按具体操作授权过滤。后端是唯一判据，这里只是别把点了必然
    if (path) {
      if (canRes('upload')) menu.push({ label: '上传', icon: <Icon kind="ui-upload" size={14} />, action: () => uploadRef.current?.click() })
      if (canRes('mkdir')) menu.push({ label: '新建文件夹', icon: <Icon kind="ui-folder-plus" size={14} />, action: handleCreateFolder })
      if (canRes('write')) menu.push({ label: '新建文件', icon: <Icon kind="ui-file-plus" size={14} />, action: handleCreateFile })
    }
    if (sel.size > 0 && path && canRes('copy')) {
      menu.push({ label: '复制', icon: <Icon kind="ui-copy" size={14} />, action: handleCopy })
    }
    if (sel.size === 1 && path && canRes('rename')) {
      menu.push({ label: '重命名', icon: <Icon kind="ui-edit" size={14} />, action: handleRename })
    }
    if (singleFile && isEditableFile(singleFile.name) && canRes('write')) {
      menu.push({ label: '编辑', icon: <Icon kind="ui-edit" size={14} />, action: () => handleEditFile(singleFile.name) })
    }
    if (singleFile && singleFile.name.toLowerCase().endsWith('.zip') && canRes('write')) {
      menu.push({ label: '解压', icon: <Icon kind="ui-unzip" size={14} />, action: () => handleUnzip(singleFile.name) })
    }
    if (clip.length > 0 && target && canRes('copy')) {
      menu.push({ label: '粘贴', icon: <Icon kind="ui-paste" size={14} />, action: () => handlePaste(target) })
    }
    if (sel.size > 0 && path) {
      if (canRes('read')) menu.push({ label: '压缩(ZIP)', icon: <Icon kind="ui-zip" size={14} />, action: handleZip })
      if (canRes('delete')) menu.push({ label: '删除', icon: <Icon kind="ui-trash" size={14} />, action: handleDelete, danger: true })
      if (canRes('read')) menu.push({ label: '下载', icon: <Icon kind="ui-download" size={14} />, action: downloadSelected })
    }
    return menu
  }

  const menuItems = buildMenuItems(selected, clipboard, pasteTarget, currentPath)

  const renderNameCell = (item) => {
    const isEditing = editingItem && editingItem.name === item.name
    if (!isEditing) {
      return (
        <span className={`res-col-name ${item.isPending ? 'is-pending' : ''}`}>
          <span className="file-icon">{item.is_dir ? <Icon kind="ui-folder" /> : <Icon kind="ui-file" />}</span>
          <span
            className={`file-name ${item.is_dir ? 'is-dir' : ''}`}
            onClick={(e) => {
              e.stopPropagation()
              if (item.is_dir) browse(joinPath(currentPath, item.name))
            }}
          >
            {item.name}
          </span>
          {item.isPending && <span className="file-pending-icon" title="处理中"><Icon kind="ui-spinner" size={12} /></span>}
        </span>
      )
    }
    return (
      <span className="res-col-name res-col-editing">
        <span className="file-icon">{editingItem.isFile ? <Icon kind="ui-file" /> : <Icon kind="ui-folder" />}</span>
        <input
          ref={editInputRef}
          className="res-edit-name-input"
          value={editValue}
          onChange={(e) => setEditValue(e.target.value)}
          onBlur={handleEditBlur}
          onKeyDown={handleEditKeyDown}
        />
      </span>
    )
  }

  const totalCountText = currentPath
    ? `共 ${total} 项`
    : `共 ${drives.length} 个分区`

  const pageCount = Math.ceil(total / PAGE_SIZE)

  return (
    <div className="res-manager">
      {error && <div className="res-error">{error}</div>}

      {loading && (
        <div className="res-loading-toast">
          <span className="res-loading-spinner"><Icon kind="ui-refresh" size={14} /></span>
          <span>加载中，请稍等...</span>
        </div>
      )}

      <div className="res-file-list">
        <div className="res-file-toolbar">
          <div className="res-breadcrumb">
            <button className="res-icon-btn" onClick={goHome} title="返回所有分区"><Icon kind="ui-home" /></button>
            {currentPath && (
              <>
                <button className="res-icon-btn" onClick={() => browse(currentPath)} title="刷新"><Icon kind="ui-refresh" /></button>
                <button className="res-icon-btn" onClick={handleBack} disabled={isAtRoot} title="上级目录"><Icon kind="ui-arrow-left" /></button>
                <span className="res-path">{currentPath}</span>
              </>
            )}
            {!currentPath && (
              <span className="res-path">所有分区</span>
            )}
          </div>
          <input ref={uploadRef} type="file" style={{ display: 'none' }} onChange={handleUpload} />
        </div>

        {!currentPath && !loading && (
          <div className="res-drives">
            {drives.length === 0 ? (
              <div className="res-empty">未检测到磁盘</div>
            ) : drives.map((d) => {
              const isWin = /^[a-zA-Z]:/.test(d.path)
              const displayName = isWin
                ? d.name
                : (d.path === '/' ? '/' : d.path.split('/').filter(Boolean).slice(-2).join('/') || '/')
              const isSelected = targetDrive === d.path
              return (
                <div
                  key={d.name}
                  className={`res-drive-card ${isSelected ? 'is-selected' : ''}`}
                  onClick={() => handleDriveClick(d)}
                  onContextMenu={(e) => openContextMenu(e, null)}
                  title={clipboard.length > 0
                    ? (isSelected ? '再次点击进入该分区' : '点击选为粘贴目标')
                    : '点击进入该分区'}
                >
                  <div className="drive-icon"><Icon kind="ui-disk" size={36} /></div>
                  <div className="drive-name">{displayName}</div>
                  <div className="drive-fstype">{d.fstype || '—'}</div>
                  <div className="drive-bar">
                    <div className="drive-bar-fill" style={{ width: `${d.total_gb ? (d.used_gb / d.total_gb * 100) : 0}%` }} />
                  </div>
                  <div className="drive-info">
                    {d.free_gb} GB 可用 / {d.total_gb} GB
                  </div>
                  {clipboard.length > 0 && (
                    <div className="drive-paste-hint">
                      {isSelected ? '已选为粘贴目标，再点击进入' : '点击选为粘贴目标'}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}

        {currentPath && !loading && (
          <>
            <div className="res-list-header">
              <span className="res-col-name" onClick={() => sort('name')}>
                名称
                {sortKey === 'name' && <Icon kind={sortAsc ? 'ui-chevron-up' : 'ui-chevron-down'} size={11} />}
              </span>
              <span className="res-col-date" onClick={() => sort('mtime')}>
                修改日期 {sortKey === 'mtime' && <Icon kind={sortAsc ? 'ui-chevron-up' : 'ui-chevron-down'} size={11} />}
              </span>
              <span className="res-col-size" onClick={() => sort('size')}>
                大小 {sortKey === 'size' && <Icon kind={sortAsc ? 'ui-chevron-up' : 'ui-chevron-down'} size={11} />}
              </span>
            </div>
            <div
              className="res-file-list-body"
              ref={listBodyRef}
              onContextMenu={(e) => openContextMenu(e, null)}
            >
              {sorted.length === 0 ? (
                <div className="res-empty">空目录</div>
              ) : sorted.map((item) => {
                const isSel = selected.has(item.name)
                return (
                  <div
                    key={item.name}
                    className={`res-file-row ${isSel ? 'is-selected' : ''} ${item.isPending ? 'is-pending-row' : ''}`}
                    onClick={(e) => handleRowClick(e, item)}
                    onContextMenu={(e) => openContextMenu(e, item)}
                  >
                    {renderNameCell(item)}
                    <span className="res-col-date">{item.mtime}</span>
                    <span className="res-col-size">{item.is_dir ? '-' : fmtSize(item.size)}</span>
                  </div>
                )
              })}
            </div>
          </>
        )}

        <div className="res-status-bar">
          <div className="res-status-left">
            <span className="res-status-count">{totalCountText}</span>
            {status.text && (
              <span className={`res-status-msg res-status-${status.type}`}>
                {status.type === 'loading' && <span className="res-status-spinner"><Icon kind="ui-spinner" size={12} /></span>}
                {status.text}
              </span>
            )}
          </div>
          {currentPath && pageCount > 1 && (
            <div className="res-status-pagination">
              <button disabled={page <= 1} onClick={() => browse(currentPath, page - 1)}>上一页</button>
              <span>{page} / {pageCount}</span>
              <button disabled={page >= pageCount} onClick={() => browse(currentPath, page + 1)}>下一页</button>
            </div>
          )}
        </div>
      </div>

      {contextMenu && menuItems.length > 0 && (
        <ul
          ref={menuRef}
          className="res-context-menu"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={(e) => e.stopPropagation()}
        >
          {menuItems.map((item) => (
            <li
              key={item.label}
              className={item.danger ? 'danger' : ''}
              onClick={() => {
                setContextMenu(null)
                item.action()
              }}
            >
              {item.icon}
              {item.label}
            </li>
          ))}
        </ul>
      )}

      {editor && (
        <div
          className="res-editor-overlay"
          onMouseDown={(e) => { if (e.target === e.currentTarget) closeEditor() }}
        >
          <div className="res-editor-modal">
            <div className="res-editor-header">
              <Icon kind="ui-file" size={15} />
              <span className="res-editor-name">{editor.name}</span>
              <span className="res-editor-path" title={editor.path}>{editor.path}</span>
              <div className="res-editor-actions">
                <button
                  className="res-editor-btn primary"
                  onClick={handleSaveEditor}
                  disabled={editor.loading || editor.saving}
                >
                  {editor.saving ? '保存中...' : '保存'}
                </button>
                <button className="res-editor-btn" onClick={closeEditor} disabled={editor.saving}>
                  关闭
                </button>
              </div>
            </div>
            <textarea
              className="res-editor-textarea"
              value={editorValue}
              onChange={(e) => setEditorValue(e.target.value)}
              onKeyDown={handleEditorKeyDown}
              spellCheck={false}
              disabled={editor.loading}
              placeholder={editor.loading ? '正在读取文件内容...' : ''}
            />
            <div className="res-editor-footer">
              <span>{editor.loading ? '读取中...' : `${fmtSize(editor.size)} · UTF-8 · Ctrl+S 保存`}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
