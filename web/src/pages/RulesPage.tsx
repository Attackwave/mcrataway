import { useQuery } from '@tanstack/react-query'
import { getRules } from '../api/client'
import { RuleEditor } from '../components/RuleEditor'

export default function RulesPage() {
  const { data: packs, isLoading } = useQuery({
    queryKey: ['rules'],
    queryFn: getRules,
  })

  return (
    <div className="space-y-6">
      <h2 className="text-lg font-semibold">Rule Packs</h2>
      <RuleEditor packs={packs ?? []} isLoading={isLoading ?? false} />
    </div>
  )
}
