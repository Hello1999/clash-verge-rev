import {
  Box,
  Button,
  Chip,
  LinearProgress,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TextField,
  Typography,
} from '@mui/material'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import type { AutoChainExit, AutoChainRouteStatus } from '@/services/cmds'

export const AutoChainResults = ({
  routes,
  selected,
  exits,
  sources,
  manual,
  busy,
  onSelect,
}: {
  routes: AutoChainRouteStatus[]
  selected: string | null
  exits: AutoChainExit[]
  sources?: string[] | null
  manual: boolean
  busy: boolean
  onSelect: (name: string) => Promise<void>
}) => {
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(0)
  const completed = routes.filter((route) => route.checked_at).length
  const entries = new Map<string, AutoChainExit[]>()
  for (const node of exits) {
    if (
      !sources ||
      sources.some(
        (source) =>
          node.source === source ||
          node.source.startsWith(`${source}/provider/`),
      )
    )
      entries.set(node.route_id, [...(entries.get(node.route_id) ?? []), node])
  }
  const nodes = routes
    .flatMap((route) => {
      const id = route.name.slice(route.name.lastIndexOf(' / ') + 3)
      const aliases = entries.get(id) ?? []
      return (aliases.length ? aliases : [undefined]).map((entry) => ({
        key: JSON.stringify([route.name, entry?.source, entry?.name]),
        shared: aliases.length > 1,
        ...route,
        label:
          entry?.name ??
          route.name
            .replace('CV Chain / ', '')
            .replace(/ \/ [a-f0-9]{12}$/, ''),
        source:
          entry?.source === 'runtime'
            ? t('proxies.autoChain.runtimeSource')
            : (entry?.source_label ?? '—'),
      }))
    })
    .filter((route) =>
      `${route.label} ${route.source}`
        .toLowerCase()
        .includes(search.toLowerCase()),
    )
    .sort(
      (a, b) =>
        Number(b.alive) - Number(a.alive) ||
        (a.delay ?? Infinity) - (b.delay ?? Infinity) ||
        a.name.localeCompare(b.name),
    )
  const currentPage = Math.min(
    page,
    Math.max(0, Math.ceil(nodes.length / 10) - 1),
  )

  return (
    <Stack spacing={1}>
      <Typography variant="subtitle2">
        {t('proxies.autoChain.results')}
      </Typography>
      <Typography variant="body2" color="text.secondary">
        {t('proxies.autoChain.progress', { completed, total: routes.length })}
      </Typography>
      <LinearProgress
        aria-label={t('proxies.autoChain.progress', {
          completed,
          total: routes.length,
        })}
        variant="determinate"
        value={routes.length ? (completed / routes.length) * 100 : 0}
      />
      <Typography variant="caption" color="text.secondary">
        {t('proxies.autoChain.resultsHint')}
      </Typography>
      <TextField
        size="small"
        label={t('proxies.autoChain.search')}
        value={search}
        onChange={(event) => {
          setSearch(event.target.value)
          setPage(0)
        }}
      />
      <TableContainer sx={{ maxHeight: 300 }}>
        <Table
          stickyHeader
          size="small"
          aria-label={t('proxies.autoChain.results')}
        >
          <TableHead>
            <TableRow>
              <TableCell>{t('proxies.autoChain.relay')}</TableCell>
              <TableCell>{t('proxies.autoChain.connectivity')}</TableCell>
              <TableCell>{t('proxies.autoChain.latency')}</TableCell>
              <TableCell>{t('proxies.autoChain.checkedAt')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {nodes
              .slice(currentPage * 10, currentPage * 10 + 10)
              .map((route) => (
                <TableRow key={route.key} selected={route.name === selected}>
                  <TableCell sx={{ minWidth: 140, overflowWrap: 'anywhere' }}>
                    <Button
                      size="small"
                      disabled={busy}
                      onClick={() => void onSelect(route.name)}
                      sx={{ textAlign: 'left', textTransform: 'none' }}
                    >
                      {route.label}
                    </Button>
                    <Typography variant="caption" color="text.secondary">
                      {route.source}
                    </Typography>
                    {route.shared && (
                      <Typography
                        variant="caption"
                        sx={{ display: 'block' }}
                        color="text.secondary"
                      >
                        {t('proxies.autoChain.sharedResult')}
                      </Typography>
                    )}
                    {route.name === selected && (
                      <Box>
                        <Chip
                          size="small"
                          label={t(
                            manual
                              ? 'proxies.autoChain.manual'
                              : 'proxies.autoChain.current',
                          )}
                        />
                      </Box>
                    )}
                  </TableCell>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>
                    <Chip
                      size="small"
                      variant="outlined"
                      color={
                        !route.fresh
                          ? 'default'
                          : route.alive
                            ? 'success'
                            : 'error'
                      }
                      label={
                        !route.checked_at
                          ? t('proxies.autoChain.pending')
                          : !route.fresh
                            ? t('proxies.autoChain.stale')
                            : route.alive
                              ? t('proxies.autoChain.reachable')
                              : t('proxies.autoChain.failed')
                      }
                    />
                  </TableCell>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>
                    {route.delay === null ? '—' : `${route.delay} ms`}
                  </TableCell>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>
                    {route.checked_at
                      ? new Date(route.checked_at).toLocaleTimeString()
                      : '—'}
                  </TableCell>
                </TableRow>
              ))}
            {!nodes.length && (
              <TableRow>
                <TableCell colSpan={4}>
                  {t('proxies.autoChain.noResults')}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
      <TablePagination
        component="div"
        count={nodes.length}
        page={currentPage}
        rowsPerPage={10}
        rowsPerPageOptions={[10]}
        labelDisplayedRows={({ from, to, count }) =>
          t('proxies.autoChain.page', { from, to, count })
        }
        getItemAriaLabel={(type) =>
          type === 'next'
            ? t('proxies.autoChain.next')
            : t('proxies.autoChain.previous')
        }
        onPageChange={(_, value) => setPage(value)}
      />
    </Stack>
  )
}
