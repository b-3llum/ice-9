import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { intelApi } from '../../api/intel'
import type { SubjectProfile as SubjectProfileType } from '../../types'
import SusceptibilityRadar from './SusceptibilityRadar'
import SimulationPanel from './SimulationPanel'

interface Props {
  campaignId: string
  profile: SubjectProfileType
}

export default function SubjectProfile({ campaignId, profile }: Props) {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-ice-900 rounded-lg p-4 border border-gray-700">
        <div className="flex justify-between items-start">
          <div>
            <h3 className="text-xl font-bold text-gray-100">
              {profile.organizational_role || 'Unknown Role'}
            </h3>
            <div className="text-gray-400 text-sm mt-1">
              {profile.department || 'Unknown Department'}
            </div>
          </div>
          <span className="text-xs bg-gray-700 text-gray-300 px-2 py-1 rounded">
            {profile.entity_id.slice(0, 8)}
          </span>
        </div>
      </div>

      {/* Contact */}
      {(profile.emails.length > 0 || Object.keys(profile.social_accounts).length > 0) && (
        <Section title="Contact">
          {profile.emails.length > 0 && (
            <div className="mb-2">
              <span className="text-xs text-gray-500">Emails:</span>
              <div className="space-y-0.5">
                {profile.emails.map(e => (
                  <div key={e} className="text-gray-300 text-sm font-mono">{e}</div>
                ))}
              </div>
            </div>
          )}
          {Object.keys(profile.social_accounts).length > 0 && (
            <div>
              <span className="text-xs text-gray-500">Social Accounts:</span>
              {Object.entries(profile.social_accounts).map(([platform, url]) => (
                <div key={platform} className="text-gray-300 text-sm">
                  <span className="text-gray-500">{platform}:</span> {url}
                </div>
              ))}
            </div>
          )}
        </Section>
      )}

      {/* Digital Footprint */}
      {Object.keys(profile.digital_footprint).length > 0 && (
        <Section title="Digital Footprint">
          <div className="grid grid-cols-2 gap-2">
            {Object.entries(profile.digital_footprint).map(([k, v]) => (
              <div key={k} className="bg-gray-800 rounded px-3 py-2">
                <div className="text-xs text-gray-500">{k.replace(/_/g, ' ')}</div>
                <div className="text-sm text-gray-200">
                  {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* SE Susceptibility */}
      {Object.keys(profile.susceptibility_scores).length > 0 && (
        <Section title="SE Susceptibility">
          <SusceptibilityRadar scores={profile.susceptibility_scores} />
        </Section>
      )}

      {/* Recommended Approaches */}
      {profile.recommended_pretexts.length > 0 && (
        <Section title="Recommended Approaches">
          <div className="space-y-2">
            {profile.recommended_pretexts.map((pretext, i) => (
              <div key={i} className="bg-gray-800 rounded p-3">
                <div className="font-medium text-gray-200 text-sm">
                  {String(pretext.name || pretext.scenario_name || `Pretext ${i + 1}`)}
                </div>
                <div className="text-gray-400 text-xs mt-1">
                  {String(pretext.description || '')}
                </div>
                {pretext.estimated_success_rate != null && (
                  <div className="text-green-400 text-xs mt-1">
                    Est. success: {Math.round(Number(pretext.estimated_success_rate) * 100)}%
                  </div>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Simulation */}
      <SimulationPanel campaignId={campaignId} profileId={profile.id} />
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-ice-900 rounded-lg p-4 border border-gray-700">
      <h4 className="text-sm font-semibold text-gray-400 uppercase mb-3">{title}</h4>
      {children}
    </div>
  )
}
