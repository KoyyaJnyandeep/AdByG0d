export function downloadBlobFile(filename: string, blob: Blob) {
  if (typeof window === 'undefined' || typeof document === 'undefined') return

  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.rel = 'noopener'
  anchor.style.display = 'none'
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1500)
}

export function downloadTextFile(filename: string, content: string, mimeType = 'text/plain;charset=utf-8') {
  downloadBlobFile(filename, new Blob([content], { type: mimeType }))
}


export function downloadBase64File(filename: string, base64Content: string, mimeType = 'application/octet-stream') {
  if (typeof window === 'undefined') return

  const normalized = base64Content.replace(/\s+/g, '')
  const binary = window.atob(normalized)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  downloadBlobFile(filename, new Blob([bytes], { type: mimeType }))
}
