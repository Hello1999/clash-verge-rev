import { LanOutlined, LanRounded, WarningRounded } from '@mui/icons-material'
import { Box, Button, ButtonGroup } from '@mui/material'
import { useLockFn } from 'ahooks'
import { useCallback, useEffect, useReducer, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { BasePage, TooltipIcon } from '@/components/base'
import { AutoChain, AutoChainCurrent } from '@/components/proxy/auto-chain'
import { ClaudeGuard } from '@/components/proxy/claude-guard'
import { ProviderButton } from '@/components/proxy/provider-button'
import { ProxyGroups } from '@/components/proxy/proxy-groups'
import { useProfiles } from '@/hooks/use-profiles'
import { useVerge } from '@/hooks/use-verge'
import {
  useAppRefreshers,
  useClashConfigData,
} from '@/providers/app-data-context'
import {
  getRuntimeProxyChainConfig,
  patchClashMode,
  updateProxyChainConfigInRuntime,
} from '@/services/cmds'
import { showNotice } from '@/services/notice-service'
import { debugLog } from '@/utils/debug'

const MODES = ['rule', 'global', 'direct'] as const
type Mode = (typeof MODES)[number]
const MODE_SET = new Set<string>(MODES)
const isMode = (value: unknown): value is Mode =>
  typeof value === 'string' && MODE_SET.has(value)

const ProxyPage = () => {
  const { t } = useTranslation()
  const { verge } = useVerge()
  const { profiles } = useProfiles()
  const autoChainEnabled =
    verge?.auto_chain?.enabled &&
    verge.auto_chain.profile_uid === profiles?.current

  // 从 localStorage 恢复链式代理按钮状态
  const [isChainMode, setIsChainMode] = useState(() => {
    try {
      const saved = localStorage.getItem('proxy-chain-mode-enabled')
      return saved === 'true'
    } catch {
      return false
    }
  })

  const [chainConfigData, dispatchChainConfigData] = useReducer(
    (_: string | null, action: string | null) => action,
    null as string | null,
  )

  const { clashConfig } = useClashConfigData()
  const { refreshClashConfig } = useAppRefreshers()

  const updateChainConfigData = useCallback((value: string | null) => {
    dispatchChainConfigData(value)
  }, [])

  const normalizedMode = clashConfig?.mode?.toLowerCase()
  const curMode = isMode(normalizedMode) ? normalizedMode : undefined
  const chainWarning = t('proxies.page.chain.warning')

  const onChangeMode = useLockFn(async (mode: Mode) => {
    try {
      // patchClashMode 在后端 PATCH 失败时会 reject，需提示用户而非静默失败
      await patchClashMode(mode)
      refreshClashConfig()
    } catch (error) {
      showNotice.error(error)
    }
  })

  const onToggleChainMode = useLockFn(async () => {
    const newChainMode = !isChainMode

    setIsChainMode(newChainMode)
    // 保存链式代理按钮状态到 localStorage
    localStorage.setItem('proxy-chain-mode-enabled', newChainMode.toString())

    if (!newChainMode) {
      // 退出链式代理模式时，清除链式代理配置
      try {
        debugLog('Exiting chain mode, clearing chain configuration')
        await updateProxyChainConfigInRuntime(null)
        debugLog('Chain configuration cleared successfully')
      } catch (error) {
        console.error('Failed to clear chain configuration:', error)
      }
    }
  })

  // 当开启链式代理模式时，获取配置数据
  useEffect(() => {
    if (!isChainMode) {
      updateChainConfigData(null)
      return
    }

    let cancelled = false

    const fetchChainConfig = async () => {
      try {
        const exitNode = localStorage.getItem('proxy-chain-exit-node')

        if (!exitNode) {
          console.error('No proxy chain exit node found in localStorage')
          if (!cancelled) {
            updateChainConfigData('')
          }
          return
        }

        const configData = await getRuntimeProxyChainConfig(exitNode)
        if (!cancelled) {
          updateChainConfigData(configData || '')
        }
      } catch (error) {
        console.error('Failed to get runtime proxy chain config:', error)
        if (!cancelled) {
          updateChainConfigData('')
        }
      }
    }

    fetchChainConfig()

    return () => {
      cancelled = true
    }
  }, [isChainMode, updateChainConfigData])

  useEffect(() => {
    if (normalizedMode && !isMode(normalizedMode)) {
      onChangeMode('rule')
    }
  }, [normalizedMode, onChangeMode])

  return (
    <BasePage
      full
      contentStyle={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
      }}
      title={
        isChainMode ? (
          <Box
            component="span"
            data-tauri-drag-region="true"
            sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.75 }}
          >
            {t('proxies.page.title.chainMode')}
            <TooltipIcon
              title={chainWarning}
              icon={WarningRounded}
              color="warning"
              sx={{ p: 0.25 }}
            />
          </Box>
        ) : (
          t('proxies.page.title.default')
        )
      }
      header={
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <ProviderButton />

          <ButtonGroup size="small">
            {MODES.map((mode) => (
              <Button
                key={mode}
                disabled={
                  (!!verge?.claude_guard_enabled || !!autoChainEnabled) &&
                  mode !== 'rule'
                }
                variant={mode === curMode ? 'contained' : 'outlined'}
                onClick={() => onChangeMode(mode)}
                sx={{ textTransform: 'capitalize' }}
              >
                {t(`proxies.page.modes.${mode}`)}
              </Button>
            ))}
          </ButtonGroup>

          <Button
            size="small"
            variant={isChainMode ? 'contained' : 'outlined'}
            disabled={!!autoChainEnabled}
            onClick={onToggleChainMode}
            sx={{ ml: 1 }}
            startIcon={
              isChainMode ? (
                <LanRounded fontSize="small" />
              ) : (
                <LanOutlined fontSize="small" />
              )
            }
          >
            {t('proxies.page.actions.toggleChain')}
          </Button>
          <ClaudeGuard />
          <AutoChain
            onEnabled={() => {
              setIsChainMode(false)
              localStorage.setItem('proxy-chain-mode-enabled', 'false')
              localStorage.removeItem('proxy-chain-exit-node')
              localStorage.removeItem('proxy-chain-group')
              localStorage.removeItem('proxy-chain-items')
            }}
          />
        </Box>
      }
    >
      <AutoChainCurrent />
      <Box sx={{ flex: 1, minHeight: 0 }}>
        <ProxyGroups
          mode={curMode ?? 'rule'}
          isChainMode={isChainMode}
          chainConfigData={chainConfigData}
        />
      </Box>
    </BasePage>
  )
}

export default ProxyPage
