export default function DashboardLoading() {
  return (
    <div className="animate-pulse space-y-6">
      {/* Stat cards skeleton */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-4">
            <div className="h-3 w-16 rounded bg-gray-200 dark:bg-gray-700 mb-3" />
            <div className="h-7 w-10 rounded bg-gray-200 dark:bg-gray-700" />
          </div>
        ))}
      </div>

      {/* Chart skeleton */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-5 h-40" />

      {/* Scan list skeleton */}
      <div className="space-y-3">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-4 flex gap-4 items-center">
            <div className="h-5 w-20 rounded-full bg-gray-200 dark:bg-gray-700" />
            <div className="flex-1 h-4 rounded bg-gray-200 dark:bg-gray-700" />
            <div className="h-4 w-12 rounded bg-gray-200 dark:bg-gray-700" />
          </div>
        ))}
      </div>
    </div>
  );
}
