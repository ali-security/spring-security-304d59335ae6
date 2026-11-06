/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.authentication.preauth.x509;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.cert.X509Certificate;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Tests the principal extracted by {@link X509AuthenticationFilter}'s default
 * {@link X509PrincipalExtractor}.
 */
public class X509AuthenticationFilterTests {
	private final X509AuthenticationFilter filter = new X509AuthenticationFilter();

	private MockHttpServletRequest requestWithCertificate(X509Certificate certificate) {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute("javax.servlet.request.X509Certificate",
				new X509Certificate[] { certificate });
		return request;
	}

	@Test
	public void defaultExtractorReturnsCnOfSubject() throws Exception {
		Object principal = filter
				.getPreAuthenticatedPrincipal(requestWithCertificate(X509TestUtils
						.buildTestCertificate()));
		assertThat(principal).isEqualTo("Luke Taylor");
	}

	// gh-19254
	@Test
	public void defaultExtractorReturnsMostSpecificCnWhenMultipleCns() throws Exception {
		Object principal = filter
				.getPreAuthenticatedPrincipal(requestWithCertificate(X509TestUtils
						.buildTestCertificateWithMultipleCns()));
		assertThat(principal).isEqualTo("alice");
	}

	// gh-19254
	@Test
	public void defaultExtractorIgnoresDnEmbeddedInAnotherAttribute() throws Exception {
		Object principal = filter
				.getPreAuthenticatedPrincipal(requestWithCertificate(X509TestUtils
						.buildTestCertficateWithEmbeddedDn()));
		assertThat(principal).isEqualTo("luke");
	}

	@Test
	public void noCertificateReturnsNullPrincipal() {
		assertThat(filter.getPreAuthenticatedPrincipal(new MockHttpServletRequest()))
				.isNull();
	}
}
