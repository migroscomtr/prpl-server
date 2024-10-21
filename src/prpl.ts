/**
 * @license
 * Copyright (c) 2017 The Polymer Project Authors. All rights reserved.
 * This code may only be used under the BSD style license found at
 * http://polymer.github.io/LICENSE.txt
 * The complete set of authors may be found at
 * http://polymer.github.io/AUTHORS.txt
 * The complete set of contributors may be found at
 * http://polymer.github.io/CONTRIBUTORS.txt
 * Code distributed by Google as part of the polymer project is also
 * subject to an additional IP rights grant found at
 * http://polymer.github.io/PATENTS.txt
 */

import * as capabilities from 'browser-capabilities';
import * as express from 'express';
import * as fs from 'fs';
import * as http from 'http';
import * as httpErrors from 'http-errors';
import * as path from 'path';
import * as send from 'send';
import * as statuses from 'statuses';
import * as url from 'url';

import * as push from './push';

export interface Config {
  // The Cache-Control header to send for all requests except the entrypoint.
  //
  // Defaults to `max-age=60`.
  cacheControl?: string;

  // If `true`, when a 404 or other HTTP error occurs, the Express `next`
  // function will be called with the error, so that it can be handled by
  // downstream error handling middleware.
  //
  // If `false` (or if there was no `next` function because Express is not
  // being used), a minimal `text/plain` error will be returned.
  //
  // Defaults to `false`.
  forwardErrors?: boolean;

  // Serves a tiny self-unregistering service worker for any request path
  // ending with `service-worker.js` that would otherwise have had a 404 Not
  // Found response.
  //
  // This can be useful when the location of a service worker has changed, as
  // it will prevent clients from getting stuck with an old service worker
  // indefinitely.
  //
  // This problem arises because when a service worker updates, a 404 is
  // treated as a failed update. It does not cause the service worker to be
  // unregistered. See https://github.com/w3c/ServiceWorker/issues/204 for more
  // discussion of this problem.
  //
  // Defaults to `true`.
  unregisterMissingServiceWorkers?: boolean;

  // Below is the subset of the polymer.json specification that we care about
  // for serving. https://www.polymer-project.org/2.0/docs/tools/polymer-json
  // https://github.com/Polymer/polymer-project-config/blob/master/src/index.ts
  entrypoint?: string;
  builds?: {
    name?: string,
    browserCapabilities?: capabilities.BrowserCapability[],
  }[];
  username?: string;
  password?: string;
}

// Matches URLs like "/foo/bar.png" but not "/foo.png/bar".
const hasFileExtension = /\.[^/]*$/;

// TODO Service worker location should be configurable.
const isServiceWorker = /service-worker.js$/;

/**
 * Return a new HTTP handler to serve a PRPL-style application.
 */
export function makeHandler(root?: string, config?: Config): (
    request: http.IncomingMessage,
    response: http.ServerResponse,
    next?: express.NextFunction) => void {
  const absRoot = path.resolve(root || '.');
  console.info(`Serving files from "${absRoot}".`);

  const builds = loadBuilds(absRoot, config);

  const cacheControl = (config && config.cacheControl) || 'max-age=60';
  const unregisterMissingServiceWorkers =
      (config && config.unregisterMissingServiceWorkers != undefined) ?
          config.unregisterMissingServiceWorkers :
          true;
  const forwardErrors = config && config.forwardErrors;

  return async function prplHandler(request, response, next) {
    const handleError = (err: httpErrors.HttpError) => {
      if (forwardErrors && next) {
        next(err);
      } else {
        writePlainTextError(response, err);
      }
    };

    const scriptSrcAllowedHosts = [
        "https://*.googlesyndication.com",
        "https://*.googletagservices.com",
        "https://www.google-analytics.com",
        "www.googletagmanager.com",
        "https://tagmanager.google.com",
        "https://googletagmanager.com",
        "*.googleapis.com",
        "*.googleadservices.com",
        "https://*.bkmexpress.com.tr",
        "https://*.masterpassturkiye.com",
        "https://challenges.cloudflare.com",
        "app.vwo.com",
        "*.visualwebsiteoptimizer.com",
        "https://js.go2sdk.com",
        "https://cdn.adjust.com",
        "https://live.maytap.me",
        "https://creativecdn.com",
        "https://*.cloudfront.net",
        "https://tags.bkrtx.com",
        "https://static.criteo.net",
        "https://connect.facebook.net",
        "https://cdn.yapaytech.com",
        "https://cdnjs.cloudflare.com",
        "https://*.criteo.com",
        "*.doubleclick.net",
        "affiliate.migros.com.tr",
        "*.bluekai.com",
        "*.mncdn.com",
        "*.adform.net",
        "*.storyly.io",
        "cdn.jsdelivr.net",
        "https://digiavantaj.cake.aclz.net",
        "*.efilli.com",
        "https://analytics.tiktok.com",
    ];

    const frameSrcAllowedHosts = [
      "https://*.youtube.com",
      "https://tr.rdrtr.com",
      "https://stags.bluekai.com",
      "https://*.criteo.com",
      "https://*.criteo.net",
      "https://*.doubleclick.net",
      "https://*.api.sociaplus.com",
      "https://*.webinstats.com",
      "https://sanalmarket.api.useinsider.com",
      "https://*.bkmexpress.com.tr",
      "https://www.linkadoo.co",
      "https://linkadoo.co",
      "https://channelconnector.smartmessage-connect.com",
      "https://*.poltio.com",
      "https://*.googlesyndication.com",
      "https://console.googletagservices.com",
      "https://digiavantaj.cake.aclz.net",
      "https://creativecdn.com",
      "https://documents.colendilabs.com",
      "https://challenges.cloudflare.com",
      "https://cdnjs.cloudflare.com",
      "app.vwo.com",
      "*.visualwebsiteoptimizer.com",
      "https://*.adjust.com",
      "maps.googleapis.com",
      "*.adform.net",
      "https://wallet.moneypay.com.tr",
      "*.googleadservices.com",
      "*.facebook.com",
      "https://analytics.tiktok.com",
    ];

    const styleSrcAllowedHosts = [
      "*.googlesyndication.com",
      "www.googletagservices.com",
      "www.googletagmanager.com",
      "fonts.googleapis.com",
      "*.visualwebsiteoptimizer.com",
      "maps.googleapis.com",
      "https://googletagmanager.com",
      "https://tagmanager.google.com",
      "https://fonts.googleapis.com",
    ];

    const imageSrcAllowedHosts = [
        "www.google.com",
        "www.google.com.tr",
        "maps.googleapis.com",
        "*.gstatic.com",
        "*.googleadservices.com",
        "*.visualwebsiteoptimizer.com",
        "*.facebook.com",
        "www.google-analytics.com",
        "*.googlesyndication.com",
        "img.youtube.com",
        "matching.ivitrack.com",
        "stags.bluekai.com",
        "x.bidswitch.net",
        "ib.adnxs.com", // criteo
        "contextual.media.net",
        "pixel.rubiconproject.com",
        "rtb-csync.smartadserver.com",
        "criteo-sync.teads.tv", // criteo
        "*.criteo.com", // criteo
        "eb2.3lift.com",
        "visitor.omnitagjs.com", // criteo
        "simage2.pubmatic.com",
        "*.ads.yieldmo.com", // criteo
        "*.doubleclick.net",
        "*.taboola.com", // criteo
        "cm.adform.net",
        "c1.adform.net",
        "*.casalemedia.com",
        "id5-sync.com",
        "ad.360yield.com",
        "jadserve.postrelease.com",
        "eb2.3lift.com",
        "x.bidswitch.net",
        "match.sharethrough.com", // criteo
        "jadserve.postrelease.com", // criteo
        "*.emxdgt.com",
        "ups.analytics.yahoo.com",
        "exchange.mediavine.com",
        "sync.outbrain.com",
        "trends.revcontent.com",
        "https://sync.1rx.io", // criteo
        "criteo-partners.tremorhub.com", // criteo
        "ad.yieldlab.net",
        "*.migros.com.tr",
        "magaza-iphone.migros.com.tr",
        "*.demdex.net",
        "*.krxd.net",
        "*.cloudfront.net",
        "*.thebrighttag.com",
        "*.semasio.net",
        "*.dmxleo.com",
        "https://googletagmanager.com",
        "www.googletagmanager.com",
        "https://ssl.gstatic.com",
        "https://www.gstatic.com",
        "https://digiavantaj.cake.aclz.net",
        "https://documents.colendilabs.com",
        "https://uploads-ssl.webflow.com", // efilli
        "*.efilli.com",
        "https://analytics.tiktok.com",
    ];

    // json, html etc
    const defaultFallbackAllowedHosts = [
        "*.migros.com.tr",
        "exchange.mediavine.com", // criteo
        "e1.emxdgt.com",
        "*.analytics.yahoo.com",
        "sync.outbrain.com", // criteo
        "trends.revcontent.com",
        "match.sharethrough.com",
        "criteo-partners.tremorhub.com",
        "trends.revcontent.com", // criteo
        "tazedirekt.webinstats.com",
        "macro.webinstats.com",
        "*.facebook.com",
        "maps.googleapis.com",
        "https://*.cloudfront.net",
    ];

    const connectSrcAllowedHosts = [
        "analytics.google.com",
        "macro.webinstats.com",
        "tazedirekt.webinstats.com",
        "*.gstatic.com",
        "logs.browser-intake-datadoghq.eu",
        "*.adjust.com",
        "app.adjust.net.in",
        "app.adjust.world",
        "*.dahi.ai",
        "*.adrttt.com",
        "https://*.migrosone.com",
        "*.facebook.com",
        "www.google.com",
        "www.google.com.tr",
        "magaza-iphone.migros.com.tr",
        "*.rubiconproject.com",
        ...scriptSrcAllowedHosts
    ];

    response.setHeader('Content-Security-Policy',
        `default-src 'self' 'unsafe-inline' 'unsafe-eval' ${defaultFallbackAllowedHosts.join(' ')}; `
        + `script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: ${scriptSrcAllowedHosts.join(' ')} ; `
        + `connect-src 'self' ${connectSrcAllowedHosts.join(' ')} ; `
        + "font-src 'self' data: https://fonts.gstatic.com ; "
        + `img-src data: blob: 'self' 'unsafe-inline' https://*.migrosone.com ${imageSrcAllowedHosts.join(' ')} ; `
        + `frame-src ${frameSrcAllowedHosts.join(' ')} ; `
        + `style-src 'self' 'unsafe-inline' ${styleSrcAllowedHosts.join(' ')} ;`
        + `manifest-src 'self' ; `
        + "worker-src 'self' blob: ;"
        + "object-src 'none' ;");

    response.setHeader('X-Frame-Options', 'SAMEORIGIN');
    response.setHeader('Strict-Transport-Security', 'max-age=0; includeSubDomains');
    response.setHeader('X-XSS-Protection', 1);
    response.setHeader('X-Content-Type-Options', 'nosniff');


    const urlPath = url.parse(request.url || '/').pathname || '/';

    // Let's be extra careful about directory traversal attacks, even though
    // the `send` library should already ensure we don't serve any file outside
    // our root. This should also prevent the file existence check we do next
    // from leaking any file existence information (whether you got the
    // entrypoint or a 403 from `send` might tell you if a file outside our
    // root exists). Add the trailing path separator because otherwise "/foo"
    // is a prefix of "/foo-secrets".
    const absFilepath = path.normalize(path.join(absRoot, urlPath));
    if (!absFilepath.startsWith(addTrailingPathSep(absRoot))) {
      handleError(httpErrors(403, 'Forbidden'));
      return;
    }

    // Serve the entrypoint for the root path, and for all other paths that
    // don't have a corresponding static resource on disk. As a special
    // case, paths with file extensions are always excluded because they are
    // likely to be not-found static resources rather than application
    // routes.
    const serveEntrypoint = urlPath === '/' ||
        (!hasFileExtension.test(urlPath) && !(await fileExists(absFilepath)));

    // Find the highest ranked build suitable for this user agent.
    const clientCapabilities = capabilities.browserCapabilities(
        request.headers['user-agent'] as string);
    const build = builds.find((b) => b.canServe(clientCapabilities));

    // We warned about this at startup. You should probably provide a fallback
    // build with no capabilities, at least to nicely inform the user. Note
    // that we only return this error for the entrypoint; we always serve fully
    // qualified static resources.
    if (!build && serveEntrypoint) {
      handleError(httpErrors(500, 'This browser is not supported.'));
      return;
    }

    const fileToSend = (build && serveEntrypoint) ? build.entrypoint : urlPath;

    if (isServiceWorker.test(fileToSend)) {
      // A service worker may only register with a scope above its own path if
      // permitted by this header.
      // https://www.w3.org/TR/service-workers-1/#service-worker-allowed
      response.setHeader('Service-Worker-Allowed', '/');

      // Don't cache SW (unless cache header is otherwise set).
      if (!response.getHeader('Cache-Control')) {
        response.setHeader('Cache-Control', 'max-age=0');
      }

      // Automatically unregister service workers that no longer exist to
      // prevent clients getting stuck with old service workers indefinitely.
      if (unregisterMissingServiceWorkers && !(await fileExists(absFilepath))) {
        response.setHeader('Content-Type', 'application/javascript');
        response.writeHead(200);
        response.end(
            `self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', () => self.registration.unregister());`);
        return;
      }
    }

    // Don't set the Cache-Control header if it's already set. This way another
    // middleware can control caching, and we won't touch it.
    if (!response.getHeader('Cache-Control')) {
      response.setHeader(
          'Cache-Control', serveEntrypoint ? 'max-age=0' : cacheControl);
    }

    if (build && build.pushManifest) {
      // Set nopush attribute if the client doesn't support push. This will
      // still set preload headers, but it provides a signal to the server to
      // not use server push.
      const nopush = !clientCapabilities.has('push');
      const linkHeaders = build.pushManifest.linkHeaders(urlPath, nopush);
      if (urlPath !== fileToSend) {
        // Also check the filename against the push manifest. In the case of
        // the entrypoint, these will be different (e.g. "/my/app/route" vs
        // "/es2015/index.html"), and we want to support configuring pushes in
        // terms of both.
        linkHeaders.push(...build.pushManifest.linkHeaders(fileToSend, nopush));
      }
      response.setHeader('Link', linkHeaders);
    }

    const sendOpts = {
      root: absRoot,
      // We handle the caching header ourselves.
      cacheControl: false,
    };
    send(request, fileToSend, sendOpts)
        .on('error',
            (err: httpErrors.HttpError) => {
              // `send` puts a lot of detail in the error message, like the
              // absolute system path of the missing file for a 404. We don't
              // want that to leak out, so let's use a generic message instead.
              err.message = statuses.message[err.status] || String(err.status);
              handleError(err);
            })
        .pipe(response);
  };
}

/**
 * Return a promise for the existence of a file.
 */
function fileExists(filepath: string): Promise<boolean> {
  return new Promise((resolve) => fs.access(filepath, (err) => resolve(!err)));
}

/**
 * Write a plain text HTTP error response.
 */
function writePlainTextError(
    response: http.ServerResponse, error: httpErrors.HttpError) {
  response.statusCode = error.status;
  response.setHeader('Content-Type', 'text/plain');
  response.end(error.message);
}

function addTrailingPathSep(p: string): string {
  return p.endsWith(path.sep) ? p : p + path.sep;
}

class Build {
  public pushManifest?: push.PushManifest;

  constructor(
      private configOrder: number,
      public requirements: Set<capabilities.BrowserCapability>,
      public entrypoint: string,
      buildDir: string,
      serverRoot: string) {
    // TODO Push manifest location should be configurable.
    const pushManifestPath = path.join(buildDir, 'push-manifest.json');
    const relPath = path.relative(serverRoot, pushManifestPath);
    if (fs.existsSync(pushManifestPath)) {
      console.info(`Detected push manifest "${relPath}".`);
      // Note this constructor throws if invalid.
      this.pushManifest = new push.PushManifest(
          JSON.parse(fs.readFileSync(pushManifestPath, 'utf8')) as
              push.PushManifestData,
          path.relative(serverRoot, buildDir));
    }
  }

  /**
   * Order builds with more capabililties first -- a heuristic that assumes
   * builds with more features are better. Ties are broken by the order the
   * build appeared in the original configuration file.
   */
  compare(that: Build): number {
    if (this.requirements.size !== that.requirements.size) {
      return that.requirements.size - this.requirements.size;
    }
    return this.configOrder - that.configOrder;
  }

  /**
   * Return whether all requirements of this build are met by the given client
   * browser capabilities.
   */
  canServe(client: Set<capabilities.BrowserCapability>): boolean {
    for (const r of this.requirements) {
      if (!client.has(r)) {
        return false;
      }
    }
    return true;
  }
}

function loadBuilds(root: string, config: Config | undefined): Build[] {
  const builds: Build[] = [];
  const entrypoint = (config ? config.entrypoint : null) || 'index.html';

  if (!config || !config.builds || !config.builds.length) {
    // No builds were specified. Try to serve an entrypoint from the root
    // directory, with no capability requirements.
    console.warn(`WARNING: No builds configured.`);
    builds.push(new Build(0, new Set(), entrypoint, root, root));

  } else {
    for (let i = 0; i < config.builds.length; i++) {
      const build = config.builds[i];
      if (!build.name) {
        console.warn(`WARNING: Build at offset ${i} has no name; skipping.`);
        continue;
      }
      builds.push(new Build(
          i,
          new Set(build.browserCapabilities),
          path.posix.join(build.name, entrypoint),
          path.join(root, build.name),
          root));
    }
  }

  // Sort builds by preference in case multiple builds could be served to
  // the same client.
  builds.sort((a, b) => a.compare(b));

  // Sanity check.
  for (const build of builds) {
    const requirements = Array.from(build.requirements.values());
    console.info(
        `Registered entrypoint "${build.entrypoint}" with capabilities ` +
        `[${requirements.join(',')}].`);
    // Note `build.entrypoint` is relative to the server root, but that's not
    // neccessarily our cwd.
    // TODO Refactor to make filepath vs URL path and relative vs absolute
    // values clearer.
    if (!fs.existsSync(path.join(root, build.entrypoint))) {
      console.warn(`WARNING: Entrypoint "${build.entrypoint}" does not exist.`);
    }
  }
  if (!builds.find((b) => b.requirements.size === 0)) {
    console.warn(
        'WARNING: All builds have a capability requirement. ' +
        'Some browsers will display an error. Consider a fallback build.');
  }

  return builds;
}
