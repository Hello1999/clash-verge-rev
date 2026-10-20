import { AltRouteRounded, ExpandMoreRounded } from '@mui/icons-material'
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Autocomplete,
  Box,
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { useProfiles } from '@/hooks/use-profiles'
import { useVerge } from '@/hooks/use-verge'
import { useAppRefreshers } from '@/providers/app-data-context'
import {
  type AutoChainExit,
  getAutoChainOptions,
  getAutoChainStatus,
  selectAutoChainRoute,
} from '@/services/cmds'
import { showNotice } from '@/services/notice-service'
import { useQuery } from '@/services/query-client'

import { AutoChainResults } from './auto-chain-results'

const DEFAULT_URL = 'https://www.gstatic.com/generate_204'

export const AutoChain = ({ onEnabled }: { onEnabled: () => void }) => {
  const { t } = useTranslation()
  const { verge, patchVerge } = useVerge()
  const { profiles } = useProfiles()
  const { refreshProxy, refreshClashConfig } = useAppRefreshers()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [exit, setExit] = useState<AutoChainExit | null>(null)
  const [sources, setSources] = useState<string[] | null>(null)
  const [interval, setInterval] = useState(600)
  const [tolerance, setTolerance] = useState(50)
  const [url, setUrl] = useState(DEFAULT_URL)
  const saved = verge?.auto_chain
  const enabled = saved?.enabled && saved.profile_uid === profiles?.current
  const options = useQuery({
    queryKey: ['autoChainOptions', profiles?.current],
    queryFn: getAutoChainOptions,
    enabled: open,
    revalidateOnMount: true,
  })
  const live = useQuery({
    queryKey: ['autoChainStatus'],
    queryFn: getAutoChainStatus,
    enabled: open && !!enabled,
    refetchInterval: 3000,
  })
  const status = live.data
  const healthy = status?.healthy ?? 0
  const savedExit = options.data?.exits.find(
    (node) =>
      node.source === saved?.exit_source && node.name === saved?.exit_name,
  )
  const chosenExit = exit ?? savedExit ?? null
  const subscriptions = options.data?.subscriptions ?? []
  const chosenSources = sources ?? subscriptions.map((source) => source.source)
  const subscriptionLabel = (source: {
    source: string
    label: string
    count: number
  }) =>
    `${source.source === 'runtime' ? t('proxies.autoChain.runtimeSource') : source.label} (${source.count})`

  const show = () => {
    setExit(null)
    setSources(saved?.entry_sources ?? null)
    setInterval(Math.max(saved?.interval ?? 600, 600))
    setTolerance(saved?.tolerance ?? 50)
    setUrl(saved?.url ?? DEFAULT_URL)
    setOpen(true)
    void options.refetch()
  }

  const apply = async () => {
    if (!profiles?.current || !chosenExit || !chosenSources.length) return
    setBusy(true)
    try {
      await patchVerge({
        auto_chain: {
          enabled: true,
          profile_uid: profiles.current,
          entry_sources: sources,
          exit_source: chosenExit.source,
          exit_name: chosenExit.name,
          interval,
          tolerance,
          max_latency: saved?.max_latency ?? 1000,
          url,
        },
      })
      onEnabled()
      await refreshClashConfig()
      await refreshProxy()
      await live.refetch()
    } catch (error) {
      showNotice.error(error)
    } finally {
      setBusy(false)
    }
  }

  const stop = async () => {
    if (!saved) return
    setBusy(true)
    try {
      await patchVerge({ auto_chain: { ...saved, enabled: false } })
      await refreshClashConfig()
      await refreshProxy()
    } catch (error) {
      showNotice.error(error)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button
        size="small"
        variant={enabled ? 'contained' : 'outlined'}
        startIcon={<AltRouteRounded />}
        onClick={show}
      >
        {t('proxies.autoChain.title')}
      </Button>
      <Dialog
        open={open}
        onClose={() => {
          if (!busy) setOpen(false)
        }}
        fullWidth
        maxWidth="md"
      >
        <DialogTitle>{t('proxies.autoChain.title')}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <Typography variant="body2" color="text.secondary">
              {t('proxies.autoChain.description')}
            </Typography>
            <Box sx={{ p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
              <Typography variant="body2" sx={{ fontWeight: 600 }}>
                {t('proxies.autoChain.route')}
              </Typography>
              <Typography
                variant="body2"
                color="text.secondary"
                sx={{ mt: 0.5 }}
              >
                {t('proxies.autoChain.routeHint')}
              </Typography>
            </Box>
            {enabled && (
              <Alert severity={live.error || !healthy ? 'warning' : 'success'}>
                <Typography variant="body2">
                  {live.error
                    ? t('proxies.autoChain.unavailable')
                    : !status?.in_use
                      ? t('proxies.autoChain.notSelected')
                      : status?.total === 0
                        ? t('proxies.autoChain.noCandidates')
                        : healthy
                          ? t('proxies.autoChain.running', {
                              healthy,
                              total: status?.total ?? 0,
                            })
                          : status?.routes.some((route) => !route.checked_at)
                            ? t('proxies.autoChain.initialScan')
                            : t('proxies.autoChain.recovering')}
                </Typography>
                <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>
                  {saved.exit_name}
                  {status?.selected &&
                    ` · ${status.selected.replace('CV Chain / ', '').replace(/ \/ [a-f0-9]{12}$/, '')}`}
                  {!!status?.delay && ` · ${status.delay} ms`}
                  {status?.checked_at &&
                    ` · ${new Date(status.checked_at).toLocaleTimeString()}`}
                </Typography>
              </Alert>
            )}
            {options.error && (
              <Alert severity="error">
                {t('proxies.autoChain.loadFailed')}
              </Alert>
            )}
            {options.data?.warnings.map((warning) => (
              <Alert key={warning} severity="warning">
                {warning}
              </Alert>
            ))}
            <Autocomplete
              options={options.data?.exits ?? []}
              loading={options.isFetching}
              value={chosenExit}
              onChange={(_, value) => setExit(value)}
              isOptionEqualToValue={(a, b) =>
                a.source === b.source && a.name === b.name
              }
              getOptionLabel={(node) => `${node.name} (${node.source_label})`}
              disabled={busy}
              disableClearable={!!chosenExit}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label={t('proxies.autoChain.exit')}
                  helperText={t('proxies.autoChain.exitHelp')}
                />
              )}
            />
            <FormControlLabel
              control={
                <Checkbox
                  checked={sources === null}
                  disabled={busy}
                  onChange={(_, checked) =>
                    setSources(checked ? null : chosenSources)
                  }
                />
              }
              label={t('proxies.autoChain.allSources')}
            />
            <Autocomplete
              multiple
              disableCloseOnSelect
              options={subscriptions}
              value={subscriptions.filter((source) =>
                chosenSources.includes(source.source),
              )}
              onChange={(_, values) =>
                setSources(values.map((value) => value.source))
              }
              getOptionLabel={subscriptionLabel}
              isOptionEqualToValue={(a, b) => a.source === b.source}
              disabled={busy}
              loading={options.isFetching}
              renderOption={(props, option, { selected }) => {
                const { key, ...rest } = props
                return (
                  <li key={key} {...rest}>
                    <Checkbox checked={selected} tabIndex={-1} sx={{ mr: 1 }} />
                    {subscriptionLabel(option)}
                  </li>
                )
              }}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label={t('proxies.autoChain.sources')}
                  helperText={t('proxies.autoChain.sourcesHelp')}
                  error={!chosenSources.length}
                />
              )}
            />
            {enabled && status && (
              <AutoChainResults
                routes={status.routes}
                selected={status.selected}
                exits={options.data?.exits ?? []}
                sources={saved.entry_sources}
                manual={status.manual}
                busy={busy}
                onSelect={async (name) => {
                  setBusy(true)
                  try {
                    await selectAutoChainRoute(name)
                    await live.refetch()
                    await refreshProxy()
                  } catch (error) {
                    showNotice.error(error)
                  } finally {
                    setBusy(false)
                  }
                }}
              />
            )}
            <Accordion
              disableGutters
              elevation={0}
              sx={{
                border: 1,
                borderColor: 'divider',
                '&:before': { display: 'none' },
              }}
            >
              <AccordionSummary expandIcon={<ExpandMoreRounded />}>
                <Typography variant="body2">
                  {t('proxies.autoChain.advanced')}
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Stack spacing={2}>
                  <Box sx={{ display: 'flex', gap: 2 }}>
                    <TextField
                      fullWidth
                      type="number"
                      label={t('proxies.autoChain.interval')}
                      value={interval}
                      onChange={(event) =>
                        setInterval(Number(event.target.value))
                      }
                      disabled={busy}
                      slotProps={{ htmlInput: { min: 600, max: 3600 } }}
                    />
                    <TextField
                      fullWidth
                      type="number"
                      label={t('proxies.autoChain.tolerance')}
                      helperText={t('proxies.autoChain.toleranceHelp')}
                      value={tolerance}
                      onChange={(event) =>
                        setTolerance(Number(event.target.value))
                      }
                      disabled={busy}
                      slotProps={{ htmlInput: { min: 0, max: 1000 } }}
                    />
                  </Box>
                  <TextField
                    label={t('proxies.autoChain.url')}
                    value={url}
                    onChange={(event) => setUrl(event.target.value)}
                    disabled={busy}
                  />
                  <Typography variant="caption" color="text.secondary">
                    {t('proxies.autoChain.hint')}
                  </Typography>
                </Stack>
              </AccordionDetails>
            </Accordion>
            <Typography variant="caption" color="text.secondary">
              {t('proxies.autoChain.summary')}
            </Typography>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)} disabled={busy}>
            {t('proxies.autoChain.close')}
          </Button>
          {enabled && (
            <Button color="warning" onClick={stop} disabled={busy}>
              {t('proxies.autoChain.stop')}
            </Button>
          )}
          <Button
            variant="contained"
            onClick={apply}
            disabled={
              busy ||
              !chosenExit ||
              !chosenSources.length ||
              !profiles?.current ||
              interval < 600 ||
              interval > 3600 ||
              tolerance < 0 ||
              tolerance > 1000 ||
              !url.startsWith('https://')
            }
          >
            {busy
              ? t('proxies.autoChain.applying')
              : t('proxies.autoChain.apply')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  )
}

export const AutoChainCurrent = () => {
  const { t } = useTranslation()
  const { verge } = useVerge()
  const { profiles } = useProfiles()
  const saved = verge?.auto_chain
  const enabled = !!saved?.enabled && saved.profile_uid === profiles?.current
  const live = useQuery({
    queryKey: ['autoChainStatus'],
    queryFn: getAutoChainStatus,
    enabled,
    refetchInterval: 3000,
  })
  if (!enabled) return null
  const status = live.data
  const relay = status?.selected
    ?.replace('CV Chain / ', '')
    .replace(/ \/ [a-f0-9]{12}$/, '')
  return (
    <Box
      sx={{
        mx: 2,
        mt: 1,
        mb: 1,
        p: 1.5,
        border: 1,
        borderColor: 'divider',
        borderRadius: 1,
        display: 'flex',
        alignItems: 'center',
        gap: 1.5,
        flexShrink: 0,
      }}
    >
      <AltRouteRounded color="primary" />
      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Typography variant="subtitle2">
          {t('proxies.autoChain.currentChain')}
        </Typography>
        <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>
          {relay && relay !== 'REJECT'
            ? `${relay} → ${saved.exit_name}`
            : saved.exit_name}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          {live.error
            ? t('proxies.autoChain.unavailable')
            : !status
              ? t('proxies.autoChain.initialScan')
              : status.total === 0
                ? t('proxies.autoChain.noCandidates')
                : status.delay
                  ? t('proxies.autoChain.running', {
                      healthy: status.healthy,
                      total: status.total,
                    })
                  : t('proxies.autoChain.recovering')}
          {status?.checked_at &&
            ` · ${new Date(status.checked_at).toLocaleTimeString()}`}
        </Typography>
      </Box>
      <Typography
        sx={{
          whiteSpace: 'nowrap',
          color:
            !live.error && status?.delay ? 'success.main' : 'text.secondary',
          fontWeight: 600,
        }}
      >
        {!live.error && status?.delay ? `${status.delay} ms` : '—'}
      </Typography>
    </Box>
  )
}
