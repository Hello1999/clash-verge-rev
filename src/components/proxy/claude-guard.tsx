import { ShieldOutlined } from '@mui/icons-material'
import {
  Alert,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  Typography,
} from '@mui/material'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { useVerge } from '@/hooks/use-verge'
import { useAppRefreshers } from '@/providers/app-data-context'
import { getClaudeGuardStatus } from '@/services/cmds'
import { showNotice } from '@/services/notice-service'
import { useQuery } from '@/services/query-client'

export const ClaudeGuard = () => {
  const { t } = useTranslation()
  const { verge, patchVerge } = useVerge()
  const { refreshClashConfig, refreshProxy } = useAppRefreshers()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const enabled = !!verge?.claude_guard_enabled
  const status = useQuery({
    queryKey: ['claudeGuardStatus'],
    queryFn: getClaudeGuardStatus,
    enabled: open,
    refetchInterval: 3000,
  })
  const toggle = async () => {
    setBusy(true)
    try {
      await patchVerge({ claude_guard_enabled: !enabled })
      refreshClashConfig()
      refreshProxy()
      await status.refetch()
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
        sx={{ ml: 1 }}
        variant={enabled ? 'contained' : 'outlined'}
        startIcon={<ShieldOutlined />}
        onClick={() => setOpen(true)}
      >
        {t('proxies.claudeGuard.title')}
      </Button>
      <Dialog
        open={open}
        onClose={() => !busy && setOpen(false)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>{t('proxies.claudeGuard.title')}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <Typography>{t('proxies.claudeGuard.description')}</Typography>
            <Alert severity={enabled ? 'info' : 'warning'}>
              {t(
                enabled
                  ? 'proxies.claudeGuard.enabled'
                  : 'proxies.claudeGuard.disabled',
              )}
            </Alert>
            <Typography variant="body2">
              {t('proxies.claudeGuard.route')}
            </Typography>
            <Alert severity={status.data?.routing_ready ? 'info' : 'warning'}>
              {t(
                status.data?.routing_ready
                  ? 'proxies.claudeGuard.verified'
                  : 'proxies.claudeGuard.blocked',
              )}
            </Alert>
            <Typography variant="body2">
              {t('proxies.claudeGuard.mode')}
            </Typography>
            <Typography variant="subtitle2">
              {t('proxies.claudeGuard.domains')}
            </Typography>
            <Typography variant="body2">
              {status.data?.domains.join(' · ')}
            </Typography>
            <Alert severity="info">{t('proxies.claudeGuard.boundary')}</Alert>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button disabled={busy} onClick={() => setOpen(false)}>
            {t('proxies.claudeGuard.close')}
          </Button>
          {!status.data?.locked && (
            <Button
              disabled={busy}
              variant="contained"
              color={enabled ? 'warning' : 'primary'}
              onClick={toggle}
            >
              {t(
                enabled
                  ? 'proxies.claudeGuard.disable'
                  : 'proxies.claudeGuard.enable',
              )}
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </>
  )
}
