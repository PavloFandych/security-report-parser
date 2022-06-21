package main

import (
	"time"
)

type TrivyData struct {
	SchemaVersion int32
	ArtifactName  string
	ArtifactType  string
	Metadata      Metadata
	Results       []ResultsData
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
