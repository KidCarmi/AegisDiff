export default function AdminLoading() {
  return (
    <div className="animate-pulse space-y-6">
      {/* Tab bar skeleton */}
      <div className="flex gap-2 border-b border-gray-200 dark:border-gray-800 pb-0">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="h-9 w-24 rounded-t-lg bg-gray-200 dark:bg-gray-700" />
        ))}
      </div>

      {/* Stat cards skeleton */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-4">
            <div className="h-3 w-20 rounded bg-gray-200 dark:bg-gray-700 mb-3" />
            <div className="h-7 w-12 rounded bg-gray-200 dark:bg-gray-700" />
          </div>
        ))}
      </div>

      {/* Table skeleton */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 overflow-hidden">
        <div className="border-b border-gray-200 dark:border-gray-800 px-5 py-3">
          <div className="h-4 w-28 rounded bg-gray-200 dark:bg-gray-700" />
        </div>
        {[...Array(6)].map((_, i) => (
          <div key={i} className="flex items-center gap-4 px-5 py-3 border-b border-gray-100 dark:border-gray-800 last:border-0">
            <div className="h-4 w-32 rounded bg-gray-200 dark:bg-gray-700" />
            <div className="flex-1 h-4 rounded bg-gray-200 dark:bg-gray-700" />
            <div className="h-4 w-16 rounded bg-gray-200 dark:bg-gray-700" />
          </div>
        ))}
      </div>
    </div>
  );
}
