// Copyright 2014 mit.zhao.chiu@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.
package uaa

import (
	"net/url"
	"strings"
)

type ApprovalInterface interface {
	GetCurrentApprovalsByClientId() (map[string][]*DescribedApproval, error)
	UpdateApprovals([]*DescribedApproval)
	DeleteApprovalsForClient(string)
}

type DescribedApproval struct {
	Description string
}

func (m *DescribedApproval) GetDescription() string {
	return m.Description
}

func (m *DescribedApproval) SetDescription(desc string) {
	m.Description = desc
}

func GetCurrentApprovalsByClientId(u UAA) (map[string][]*DescribedApproval, error) {
	result := make(map[string][]*DescribedApproval)

	uri, err := url.Parse(u.approvalURL())
	if err != nil {
		return result, err
	}

	params := url.Values{
		"grant_type":   {"authorization_code"},
		"redirect_uri": {u.RedirectURL},
		"scope":        {u.Scope},
	}

	host := uri.Scheme + "://" + uri.Host
	client := NewClient(host, u.VerifySSL).WithBasicAuthCredentials(u.ClientID, u.ClientSecret)
	code, body, err := client.MakeRequest("GET", uri.RequestURI(), strings.NewReader(params.Encode()))
	if err != nil {
		return result, err
	}

	if code > 399 {
		return result, NewFailure(code, body)
	}

	return result, nil
}
