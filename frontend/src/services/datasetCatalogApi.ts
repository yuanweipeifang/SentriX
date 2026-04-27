export interface DatasetJsonFileOption {
  name: string
  path: string
  sample_count: number
}

export interface DatasetCsvFileOption {
  name: string
  path: string
  row_count: number
}

export interface DatasetCatalogResponse {
  ok: boolean
  root: string
  default_dataset: string
  json_files: DatasetJsonFileOption[]
  csv_files: DatasetCsvFileOption[]
}

export async function fetchDatasetCatalog(signal?: AbortSignal): Promise<DatasetCatalogResponse> {
  const response = await fetch('/api/datasets/files', {
    method: 'GET',
    headers: { Accept: 'application/json' },
    signal,
  })

  if (!response.ok) {
    throw new Error(`dataset catalog request failed: ${response.status}`)
  }

  return response.json() as Promise<DatasetCatalogResponse>
}
