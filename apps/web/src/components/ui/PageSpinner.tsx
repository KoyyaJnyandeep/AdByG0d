export default function PageSpinner() {
  return (
    <div className="flex h-full min-h-[60vh] items-center justify-center">
      <div className="h-8 w-8 rounded-full border-2 border-transparent border-t-[var(--brand)] animate-spin" />
    </div>
  )
}
