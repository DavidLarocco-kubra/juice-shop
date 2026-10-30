/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns/promises'
import net from 'node:net'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIPv4 (ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(p => Number.isNaN(p))) return true
  if (parts[0] === 10) return true
  if (parts[0] === 127) return true
  if (parts[0] === 0) return true
  if (parts[0] === 169 && parts[1] === 254) return true
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true
  if (parts[0] === 192 && parts[1] === 168) return true
  if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true
  if (parts[0] >= 224) return true
  return false
}

function isPrivateIPv6 (ip: string): boolean {
  const lower = ip.toLowerCase()
  if (lower === '::1' || lower === '::') return true
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true
  if (lower.startsWith('fe80')) return true
  if (lower.startsWith('ff')) return true
  return false
}

const ALLOWED_IMAGE_HOSTS: Record<string, string> = {
  'placekitten.com': 'https://placekitten.com',
  'picsum.photos': 'https://picsum.photos',
  'i.imgur.com': 'https://i.imgur.com',
  'imgur.com': 'https://imgur.com',
  'raw.githubusercontent.com': 'https://raw.githubusercontent.com',
  'upload.wikimedia.org': 'https://upload.wikimedia.org',
  'www.gravatar.com': 'https://www.gravatar.com',
  'gravatar.com': 'https://gravatar.com'
}

async function buildSafeFetchUrl (candidate: string): Promise<string | null> {
  let parsed: URL
  try {
    parsed = new URL(candidate)
  } catch {
    return null
  }
  if (parsed.protocol !== 'https:') return null
  const allowedBase = Object.prototype.hasOwnProperty.call(ALLOWED_IMAGE_HOSTS, parsed.hostname)
    ? ALLOWED_IMAGE_HOSTS[parsed.hostname]
    : null
  if (allowedBase === null) return null
  const safePath = parsed.pathname.replace(/[^a-zA-Z0-9._\-/]/g, '')
  if (safePath.length === 0 || safePath.includes('..')) return null
  try {
    const addresses = await dns.lookup(parsed.hostname, { all: true })
    for (const addr of addresses) {
      if (net.isIPv4(addr.address) && isPrivateIPv4(addr.address)) return null
      if (net.isIPv6(addr.address) && isPrivateIPv6(addr.address)) return null
    }
  } catch {
    return null
  }
  return `${allowedBase}${safePath}`
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const safeUrl = await buildSafeFetchUrl(url)
          if (safeUrl === null) {
            throw new Error('Blocked unsafe URL')
          }
          const response = await fetch(new URL(safeUrl).toString())
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
