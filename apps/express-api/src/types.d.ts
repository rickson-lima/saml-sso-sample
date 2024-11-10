interface IdPResponse {
  issuer: string
  inResponseTo: string
  sessionIndex: string
  nameID: string
  nameIDFormat: string
  nameQualifier: any
  spNameQualifier: string
  uid: string
  eduPersonAffiliation: string
  email: string
  preferredLanguage: string
  attributes: Attributes
}

interface Attributes {
  uid: string
  eduPersonAffiliation: string
  email: string
  preferredLanguage: string
}
