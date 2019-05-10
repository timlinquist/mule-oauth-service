/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal.builder;

import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.mule.runtime.api.util.Preconditions.checkArgument;
import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.util.MultiMap;
import org.mule.runtime.http.api.HttpService;
import org.mule.runtime.oauth.api.ClientCredentialsOAuthDancer;
import org.mule.runtime.oauth.api.builder.ClientCredentialsListener;
import org.mule.runtime.oauth.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext;
import org.mule.service.oauth.internal.DefaultClientCredentialsOAuthDancer;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;


public class DefaultOAuthClientCredentialsDancerBuilder extends AbstractOAuthDancerBuilder<ClientCredentialsOAuthDancer>
    implements OAuthClientCredentialsDancerBuilder {

  private List<ClientCredentialsListener> listeners = new LinkedList<>();
  private MultiMap<String, String> customParameters = new MultiMap<>();
  private MultiMap<String, String> customHeaders = new MultiMap<>();


  public DefaultOAuthClientCredentialsDancerBuilder(LockFactory lockProvider,
                                                    Map<String, DefaultResourceOwnerOAuthContext> tokensStore,
                                                    HttpService httpService,
                                                    MuleExpressionLanguage expressionEvaluator) {
    super(lockProvider, tokensStore, httpService, expressionEvaluator);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder encodeClientCredentialsInBody(boolean encodeClientCredentialsInBody) {
    return (OAuthClientCredentialsDancerBuilder) super.encodeClientCredentialsInBody(encodeClientCredentialsInBody);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder customParameters(Map<String, String> customParameters) {
    requireNonNull(customParameters, "customParameters cannot be null");
    this.customParameters.putAll(customParameters);

    return this;
  }

  @Override
  public OAuthClientCredentialsDancerBuilder customHeaders(Map<String, String> customHeaders) {
    requireNonNull(customHeaders, "customHeaders cannot be null");
    this.customHeaders.putAll(customHeaders);

    return this;
  }

  @Override
  public OAuthClientCredentialsDancerBuilder addListener(ClientCredentialsListener listener) {
    requireNonNull(listener, "Cannot add a null listener");
    listeners.add(listener);

    return this;
  }

  @Override
  public ClientCredentialsOAuthDancer build() {
    checkArgument(isNotBlank(clientId), "clientId cannot be blank");
    checkArgument(isNotBlank(clientSecret), "clientSecret cannot be blank");
    checkArgument(isNotBlank(tokenUrl), "tokenUrl cannot be blank");

    return new DefaultClientCredentialsOAuthDancer(clientId, clientSecret, tokenUrl, scopes, clientCredentialsLocation,
                                                   encoding, responseAccessTokenExpr, responseRefreshTokenExpr,
                                                   responseExpiresInExpr, customParametersExtractorsExprs,
                                                   resourceOwnerIdTransformer, lockProvider, tokensStore,
                                                   httpClientFactory.get(), expressionEvaluator, customParameters,
                                                   customHeaders, listeners);
  }

}
