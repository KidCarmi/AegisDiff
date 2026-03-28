export default function ReposLoading() {
  return (
    <div className="animate-pulse space-y-4">
      <div className="h-6 w-32 rounded bg-gray-200 dark:bg-gray-700" />
      {[...Array(4)].map((_, i) => (
        <div key={i} className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-4 flex items-center gap-4">
          <div className="h-8 w-8 rounded-full bg-gray-200 dark:bg-gray-700" />
          <div className="flex-1 space-y-2">
            <div className="h-4 w-48 rounded bg-gray-200 dark:bg-gray-700" />
            <div className="h-3 w-24 rounded bg-gray-200 dark:bg-gray-700" />
          </div>
          <div className="h-8 w-20 rounded-lg bg-gray-200 dark:bg-gray-700" />
        </div>
      ))}
    </div>
  );
}
