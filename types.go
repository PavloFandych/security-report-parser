package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type TrivyData struct {
	SchemaVersion int32
	ArtifactName  string
	ArtifactType  string
	Metadata      Metadata
	Results       []ResultsData
}

func (td *TrivyData) fetch(uc *UserConfig) ([]VulnerabilityData, error) {
	switch *uc.Target {
	case All:
		switch *uc.Severity {
		case All, Low:
			return td.filter(all[string], all[string]), nil
		case Critical:
			return td.filter(all[string], critical), nil
		case High:
			return td.filter(all[string], high), nil
		case Medium:
			return td.filter(all[string], medium), nil
		default:
			return nil, errors.New(UnknownSeverityLevel)
		}
	case Java:
		switch *uc.Severity {
		case All, Low:
			return td.filter(java, all[string]), nil
		case Critical:
			return td.filter(java, critical), nil
		case High:
			return td.filter(java, high), nil
		case Medium:
			return td.filter(java, medium), nil
		default:
			return nil, errors.New(UnknownSeverityLevel)
		}
	case NodeJs:
		switch *uc.Severity {
		case All, Low:
			return td.filter(nodeJs, all[string]), nil
		case Critical:
			return td.filter(nodeJs, critical), nil
		case High:
			return td.filter(nodeJs, high), nil
		case Medium:
			return td.filter(nodeJs, medium), nil
		default:
			return nil, errors.New(UnknownSeverityLevel)
		}
	default:
		switch *uc.Severity {
		case All, Low:
			return td.filter(defaultFunc, all[string]), nil
		case Critical:
			return td.filter(defaultFunc, critical), nil
		case High:
			return td.filter(defaultFunc, high), nil
		case Medium:
			return td.filter(defaultFunc, medium), nil
		default:
			return nil, errors.New(UnknownSeverityLevel)
		}
	}
}

func (td *TrivyData) filter(byTargetPredicate func(string) bool,
	bySeverityPredicate func(string) bool) []VulnerabilityData {
	result := make([]VulnerabilityData, 0)
	for _, v := range td.Results {
		if byTargetPredicate(v.Target) {
			for _, value := range v.Vulnerabilities {
				if bySeverityPredicate(value.Severity) {
					result = append(result, value)
				}
			}
		}
	}
	return result
}

func (td *TrivyData) printOut(uc *UserConfig) {
	vulnerabilities, err := td.fetch(uc)
	check(err)

	vulnerabilitiesOutput, err := json.MarshalIndent(vulnerabilities, EmptyString, Ident)
	check(err)

	if *uc.Metadata {
		metadataOutput, err := json.MarshalIndent(td.Metadata, EmptyString, Ident)
		check(err)
		fmt.Println(string(metadataOutput))
	}
	fmt.Println(string(vulnerabilitiesOutput))
}

type Metadata struct {
	OS          OS
	ImageID     string
	DiffIDs     []string
	RepoTags    []string
	RepoDigests []string
	ImageConfig ImageConfig
}

type ImageConfig struct {
	Architecture  string        `json:"architecture"`
	Container     string        `json:"container"`
	Created       time.Time     `json:"created"`
	DockerVersion string        `json:"docker_version"`
	History       []HistoryData `json:"history"`
	Os            string        `json:"os"`
	Rootfs        Rootfs        `json:"rootfs"`
	Config        Config        `json:"config"`
}

type Config struct {
	Cmd        []string
	Entrypoint []string
	Env        []string
	Image      string
	Labels     map[string]string
	User       string
}

type Rootfs struct {
	Type    string   `json:"type"`
	DiffIds []string `json:"diff_ids"`
}

type OS struct {
	Family string
	Name   string
}

type ResultsData struct {
	Target          string
	Class           string
	Type            string
	Vulnerabilities []VulnerabilityData
}

type HistoryData struct {
	Created    time.Time `json:"created"`
	CreatedBy  string    `json:"created_by"`
	EmptyLayer bool      `json:"empty_layer"`
}

type VulnerabilityData struct {
	VulnerabilityID  string
	PkgName          string
	PkgPath          string
	InstalledVersion string
	FixedVersion     string
	Layer            Layer
	SeveritySource   string
	PrimaryURL       string
	DataSource       DataSource
	Title            string
	Description      string
	Severity         string
	CweIDs           []string
	CVSS             CVSS
	References       []string
	PublishedDate    time.Time
	LastModifiedDate time.Time
}

type Layer struct {
	DiffID string
}

type DataSource struct {
	ID   string
	Name string
	URL  string
}

type CVSS struct {
	Ghsa   Ghsa   `json:"ghsa"`
	Nvd    Nvd    `json:"nvd"`
	Redhat Redhat `json:"redhat"`
}

type Ghsa struct {
	V3Vector string
	V3Score  float32
}

type Nvd struct {
	V2Vector string
	V3Vector string
	V2Score  float32
	V3Score  float32
}

type Redhat struct {
	V3Vector string
	V3Score  float32
}

type UserConfig struct {
	Path     *string
	Target   *string
	Severity *string
	Metadata *bool
}
