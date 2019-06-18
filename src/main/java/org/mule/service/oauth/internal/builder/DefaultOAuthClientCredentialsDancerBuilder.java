/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal.builder;

import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.mule.runtime.api.util.Preconditions.checkArgument;

import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.tls.TlsContextFactory;
import org.mule.runtime.api.util.Pair;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.client.proxy.ProxyConfig;
import org.mule.runtime.oauth.api.ClientCredentialsOAuthDancer;
import org.mule.runtime.oauth.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext;
import org.mule.service.oauth.internal.DefaultClientCredentialsOAuthDancer;

import java.util.Map;

import com.github.benmanes.caffeine.cache.LoadingCache;

public class DefaultOAuthClientCredentialsDancerBuilder extends AbstractOAuthDancerBuilder<ClientCredentialsOAuthDancer>
    implements OAuthClientCredentialsDancerBuilder {

  public DefaultOAuthClientCredentialsDancerBuilder(LockFactory lockProvider,
                                                    Map<String, DefaultResourceOwnerOAuthContext> tokensStore,
                                                    LoadingCache<Pair<TlsContextFactory, ProxyConfig>, HttpClient> httpClientCache,
                                                    MuleExpressionLanguage expressionEvaluator) {
    super(lockProvider, tokensStore, httpClientCache, expressionEvaluator);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder encodeClientCredentialsInBody(boolean encodeClientCredentialsInBody) {
    return (OAuthClientCredentialsDancerBuilder) super.encodeClientCredentialsInBody(encodeClientCredentialsInBody);
  }

  @Override
  public ClientCredentialsOAuthDancer build() {
    checkArgument(isNotBlank(clientId), "clientId cannot be blank");
    checkArgument(isNotBlank(clientSecret), "clientSecret cannot be blank");
    checkArgument(isNotBlank(tokenUrl), "tokenUrl cannot be blank");

    return new DefaultClientCredentialsOAuthDancer(clientId, clientSecret, tokenUrl, scopes, encodeClientCredentialsInBody,
                                                   encoding, responseAccessTokenExpr, responseRefreshTokenExpr,
                                                   responseExpiresInExpr, customParametersExtractorsExprs,
                                                   resourceOwnerIdTransformer, lockProvider, tokensStore,
                                                   httpClientFactory.get(), expressionEvaluator);
  }

}
