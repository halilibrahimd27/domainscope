/**
 * locale-data.mjs — curated, market-specific subdomain vocabularies.
 *
 * These are hand-curated from GENERAL domain knowledge of each market: business
 * departments, public services, e-commerce, accounting / e-invoicing / e-government
 * products, education, healthcare, logistics, HR, support, booking, dealer/branch
 * portals and the hosting-panel / ERP product names common in that country.
 *
 * HARD RULE: nothing here comes from any single company's DNS zone. Every entry is
 * a generic word a business in that market would plausibly use. All labels are
 * ASCII-folded (transliterated where the language is non-Latin), lowercase, and a
 * valid single DNS label — the builder validates them again anyway.
 *
 * The builder (tools/build-wordlists.mjs) writes each of these to
 * assets/data/locale/<cc>.txt, deduped and validated. loadWordlist() selects a
 * pack from the scanned domain's TLD / ccSLD.
 *
 * Consumed only by the builder; NOT part of the Pages bundle.
 */

/* Turkish market (kept + expanded from the original wordlist-tr.txt). */
const tr = [
  // yönetim / kurumsal
  'yonetim', 'yonetici', 'yonetimpanel', 'yonetimpaneli', 'panelim', 'kurumsal', 'kurumsalpanel',
  'sirket', 'firma', 'holding', 'grup', 'merkez', 'genelmudurluk', 'idari', 'icrakurulu',
  // destek / iletişim
  'destek', 'destekhatti', 'canlidestek', 'cagrimerkezi', 'yardim', 'yardimmasasi', 'sss',
  'iletisim', 'musterihizmetleri', 'musterimemnuniyeti', 'sikayet', 'talep', 'talepler',
  'geribildirim', 'anket', 'basvuru', 'basvurular', 'basvuruformu', 'form', 'formlar',
  // e-ticaret
  'magaza', 'magazam', 'magazalar', 'sanalmagaza', 'eticaret', 'eticaretpanel', 'esatis',
  'satis', 'satispanel', 'satinalma', 'sepet', 'sepetim', 'siparis', 'siparisler', 'siparistakip',
  'urun', 'urunler', 'vitrin', 'vitrinim', 'katalog', 'kampanya', 'kampanyalar', 'firsat',
  'firsatlar', 'indirim', 'indirimler', 'teklif', 'teklifal', 'tekliflerim', 'toptan', 'perakende',
  'pazaryeri', 'abonelik', 'abonelikler', 'abone', 'paketler', 'tarife', 'tarifeler',
  // ödeme / finans
  'odeme', 'odemeler', 'odemeal', 'tahsilat', 'sanalpos', 'kasa', 'banka', 'bankacilik',
  'cuzdan', 'vergi', 'beyanname', 'butce', 'finans', 'kredi', 'taksit',
  // local payment gateways (product names common in this market)
  'iyzico', 'iyzipay', 'paytr', 'sipay', 'craftgate',
  // raporlama
  'rapor', 'raporlar', 'analiz', 'istatistik',
  // muhasebe / e-dönüşüm
  'muhasebe', 'muhasebem', 'muhasebepanel', 'onmuhasebe', 'fatura', 'faturalar', 'efatura', 'e-fatura',
  'earsiv', 'e-arsiv', 'eirsaliye', 'e-irsaliye', 'edefter', 'e-defter', 'edonusum', 'e-donusum',
  'ebelge', 'e-belge', 'esmm', 'e-smm', 'emustahsil', 'gib', 'gibportal', 'tahakkuk', 'cari',
  'ekstre', 'mizan', 'defter', 'bordro', 'ebordro', 'e-bordro', 'ozluk', 'puantaj',
  // bayi / şube / lojistik
  'bayi', 'bayiler', 'bayilik', 'bayipanel', 'bayi-panel', 'bayiportal', 'sube', 'subeler',
  'franchise', 'musteri', 'musteriler', 'musteripanel', 'crmpanel', 'tedarik', 'tedarikci',
  'tedarikciler', 'depo', 'depom', 'depolar', 'stok', 'stoklar', 'lojistik', 'sevkiyat', 'nakliye',
  'teslimat', 'kargo', 'kargotakip', 'sevk', 'irsaliye',
  // üyelik / hesap
  'uye', 'uyeler', 'uyelik', 'uyeol', 'kayit', 'kayitol', 'girisyap', 'giris', 'cikis', 'sifre',
  'sifremiunuttum', 'hesap', 'hesabim', 'profilim', 'ayarlar', 'bildirimler', 'mesajlar',
  // insan kaynakları
  'ik', 'ikpanel', 'ikportal', 'insankaynaklari', 'insan-kaynaklari', 'personel', 'personelim',
  'calisan', 'calisanlar', 'izin', 'izinler', 'mesai', 'vardiya', 'kariyer', 'ilan', 'isilanlari',
  // randevu / rezervasyon
  'randevu', 'randevual', 'randevusistemi', 'randevusistem', 'rezervasyon', 'rezervasyonlar',
  // eğitim
  'ogrenci', 'ogrenciler', 'akademik', 'ogretim', 'sinav', 'sinavlar', 'sinavsonuc', 'kurs',
  'kurslar', 'sertifika', 'sertifikalar', 'egitim', 'egitimportali', 'uzaktanegitim', 'obs', 'ubs',
  'yos', 'kutuphane', 'akademi', 'dershane',
  // sağlık
  'saglik', 'esaglik', 'e-saglik', 'hastane', 'eczane', 'laboratuvar', 'tahlil', 'sonuc', 'sonuclar',
  'poliklinik', 'muayene', 'hasta', 'hastakabul',
  // kamu / belediye
  'ebelediye', 'e-belediye', 'belediye', 'vatandas', 'ruhsat', 'tapu', 'emlak', 'harita', 'haritalar',
  'ulasim', 'otobus', 'metro', 'ihale', 'ihaleler', 'sozlesme', 'sozlesmeler', 'evrak', 'edevlet',
  'e-devlet', 'kaymakamlik', 'valilik', 'nufus', 'tahsis',
  // belge / doküman
  'belge', 'belgeler', 'dokuman', 'dokumanlar', 'arsiv', 'proje', 'projeler',
  // içerik / haber
  'duyuru', 'duyurular', 'haber', 'haberler', 'bulten', 'basin', 'medya', 'galeri',
  // sektörel
  'oto', 'otomotiv', 'servis', 'yedekparca', 'emlakportal', 'insaat', 'turizm', 'otel', 'tur',
  'seyahat', 'restoran', 'menu', 'siparisver', 'rezerve',
];

/* German (DE / AT / CH). */
const de = [
  'rechnung', 'rechnungen', 'buchhaltung', 'finanzen', 'lohn', 'gehalt', 'lohnabrechnung',
  'steuer', 'steuern', 'umsatzsteuer', 'mahnung', 'zahlung', 'zahlungen', 'kasse', 'konto',
  'konten', 'bank', 'banking', 'ueberweisung', 'lastschrift', 'gutschrift', 'beleg', 'belege',
  'kundenportal', 'kundencenter', 'kundenkonto', 'kunde', 'kunden', 'kundendienst', 'kundenservice',
  'service', 'support', 'hilfe', 'kontakt', 'ticket', 'tickets', 'anfrage', 'beschwerde',
  'bestellung', 'bestellungen', 'warenkorb', 'shop', 'laden', 'markt', 'angebot',
  'angebote', 'produkte', 'produkt', 'katalog', 'preise', 'preisliste', 'gutschein', 'rabatt',
  'aktion', 'aktionen', 'grosshandel', 'einzelhandel', 'haendler', 'haendlerportal', 'partnerportal',
  'lager', 'lagerverwaltung', 'bestand', 'versand', 'lieferung', 'logistik', 'spedition', 'fracht',
  'sendungsverfolgung', 'lieferschein', 'abholung',
  'mitarbeiter', 'personal', 'personalabteilung', 'hr', 'bewerbung', 'bewerber', 'karriere',
  'stellen', 'jobs', 'urlaub', 'zeiterfassung', 'lohnbuchhaltung',
  'anmeldung', 'login', 'registrierung', 'passwort', 'benutzer', 'benutzerkonto', 'profil',
  'einstellungen', 'nachrichten', 'postfach',
  'termin', 'termine', 'terminbuchung', 'buchung', 'buchungen', 'reservierung', 'kalender',
  'schule', 'schueler', 'lernen', 'lernplattform', 'kurse', 'kurs', 'pruefung', 'pruefungen',
  'noten', 'bibliothek', 'akademie', 'studium', 'campus',
  'gesundheit', 'praxis', 'klinik', 'patient', 'patienten', 'termin-arzt', 'apotheke', 'labor',
  'befund', 'rezept',
  'buergerportal', 'buerger', 'verwaltung', 'amt', 'behoerde', 'rathaus', 'gemeinde', 'stadt',
  'antrag', 'antraege', 'formular', 'formulare', 'akte', 'akten', 'ausschreibung', 'vergabe',
  'unternehmen', 'firma', 'gesellschaft', 'zentrale', 'geschaeftsstelle', 'niederlassung', 'filiale',
  'filialen', 'standorte', 'vertrieb', 'einkauf', 'lieferant', 'lieferanten',
  'crm', 'erp', 'warenwirtschaft', 'datev', 'lexware', 'sap', 'intranet', 'extranet', 'portal',
  'dokumente', 'unterlagen', 'archiv', 'projekte', 'vertraege', 'vertrag',
  'neuigkeiten', 'nachricht', 'presse', 'newsletter', 'veranstaltungen',
  'autohaus', 'werkstatt', 'ersatzteile', 'immobilien', 'reise', 'reisen', 'hotel', 'restaurant',
  'speisekarte',
];

/* French (FR / BE, plus CH secondary). */
const fr = [
  'facture', 'factures', 'facturation', 'comptabilite', 'compta', 'finance', 'finances', 'paie',
  'salaire', 'tva', 'impots', 'taxe', 'paiement', 'paiements', 'caisse', 'compte', 'comptes',
  'banque', 'virement', 'reglement', 'devis', 'avoir', 'recu',
  'client', 'clients', 'espaceclient', 'espace-client', 'moncompte', 'mon-compte', 'service',
  'serviceclient', 'support', 'aide', 'contact', 'assistance', 'ticket', 'tickets', 'reclamation',
  'demande', 'demandes', 'formulaire', 'formulaires', 'enquete',
  'commande', 'commandes', 'panier', 'boutique', 'magasin', 'catalogue', 'produits', 'produit',
  'offre', 'offres', 'promo', 'promotions', 'remise', 'soldes', 'grossiste', 'revendeur',
  'revendeurs', 'partenaire', 'partenaires',
  'stock', 'stocks', 'entrepot', 'inventaire', 'livraison', 'livraisons', 'expedition', 'logistique',
  'transport', 'suivi', 'colis', 'bonlivraison',
  'salarie', 'personnel', 'employe', 'employes', 'rh', 'recrutement', 'candidature', 'carriere',
  'carrieres', 'emploi', 'emplois', 'conges', 'pointage',
  'connexion', 'inscription', 'motdepasse', 'utilisateur', 'profil', 'parametres', 'messages',
  'messagerie', 'notifications',
  'rendezvous', 'rendez-vous', 'reservation', 'reservations', 'agenda', 'planning',
  'etudiant', 'etudiants', 'ecole', 'cours', 'examen', 'examens', 'notes', 'bibliotheque',
  'formation', 'formations', 'campus', 'scolarite',
  'sante', 'clinique', 'patient', 'patients', 'pharmacie', 'laboratoire', 'analyses', 'ordonnance',
  'consultation',
  'citoyen', 'mairie', 'commune', 'prefecture', 'administration', 'demarches', 'guichet', 'dossier',
  'dossiers', 'marche', 'marches', 'appeloffres',
  'entreprise', 'societe', 'siege', 'agence', 'agences', 'succursale', 'filiale', 'filiales', 'sites',
  'ventes', 'achats', 'fournisseur', 'fournisseurs',
  'crm', 'erp', 'intranet', 'extranet', 'portail', 'documents', 'archives', 'projets', 'contrat',
  'contrats', 'actualites', 'presse', 'evenements',
  'garage', 'concessionnaire', 'pieces', 'immobilier', 'voyage', 'voyages', 'hotel', 'restaurant',
  'menu', 'reserver',
];

/* Spanish (ES / MX / AR / CO / CL …). */
const es = [
  'factura', 'facturas', 'facturacion', 'contabilidad', 'finanzas', 'nomina', 'nominas', 'sueldo',
  'impuestos', 'iva', 'pago', 'pagos', 'cobro', 'cobros', 'caja', 'cuenta', 'cuentas', 'banco',
  'transferencia', 'presupuesto', 'presupuestos', 'recibo', 'comprobante',
  'cliente', 'clientes', 'areacliente', 'area-cliente', 'micuenta', 'mi-cuenta', 'servicio',
  'atencion', 'atencionalcliente', 'soporte', 'ayuda', 'contacto', 'ticket', 'tickets', 'reclamo',
  'reclamos', 'solicitud', 'solicitudes', 'formulario', 'formularios', 'encuesta',
  'pedido', 'pedidos', 'carrito', 'tienda', 'comercio', 'catalogo', 'productos', 'producto', 'oferta',
  'ofertas', 'promocion', 'promociones', 'descuento', 'descuentos', 'mayorista', 'distribuidor',
  'distribuidores', 'socio', 'socios', 'sucursal', 'sucursales',
  'stock', 'almacen', 'inventario', 'bodega', 'envio', 'envios', 'entrega', 'entregas', 'logistica',
  'transporte', 'seguimiento', 'guia', 'remito',
  'empleado', 'empleados', 'personal', 'rrhh', 'recursoshumanos', 'reclutamiento', 'postulacion',
  'empleo', 'empleos', 'carrera', 'vacaciones', 'asistencia',
  'acceso', 'ingreso', 'registro', 'contrasena', 'usuario', 'perfil', 'ajustes', 'configuracion',
  'mensajes', 'notificaciones',
  'cita', 'citas', 'reserva', 'reservas', 'agenda', 'turno', 'turnos',
  'estudiante', 'estudiantes', 'alumno', 'alumnos', 'escuela', 'curso', 'cursos', 'examen',
  'examenes', 'notas', 'biblioteca', 'campus', 'aula', 'aulavirtual', 'matricula',
  'salud', 'clinica', 'paciente', 'pacientes', 'farmacia', 'laboratorio', 'analisis', 'receta',
  'consulta', 'turnosalud',
  'ciudadano', 'municipio', 'ayuntamiento', 'gobierno', 'administracion', 'tramites', 'tramite',
  'ventanilla', 'expediente', 'expedientes', 'licitacion', 'licitaciones',
  'empresa', 'compania', 'sede', 'oficina', 'oficinas', 'agencia', 'filial', 'sedes', 'ventas',
  'compras', 'proveedor', 'proveedores',
  'crm', 'erp', 'intranet', 'extranet', 'portal', 'documentos', 'archivo', 'proyectos', 'contrato',
  'contratos', 'noticias', 'prensa', 'eventos', 'boletin',
  'taller', 'concesionario', 'repuestos', 'inmobiliaria', 'viaje', 'viajes', 'hotel', 'restaurante',
  'menu', 'reservar',
];

/* Portuguese (BR / PT). */
const pt = [
  'fatura', 'faturas', 'faturamento', 'nota', 'notafiscal', 'nfe', 'nfse', 'contabilidade',
  'financeiro', 'financas', 'folha', 'salario', 'imposto', 'impostos', 'pagamento', 'pagamentos',
  'cobranca', 'caixa', 'conta', 'contas', 'banco', 'transferencia', 'boleto', 'orcamento', 'recibo',
  'cliente', 'clientes', 'areacliente', 'area-cliente', 'minhaconta', 'minha-conta', 'atendimento',
  'suporte', 'ajuda', 'contato', 'chamado', 'chamados', 'reclamacao', 'solicitacao', 'solicitacoes',
  'formulario', 'formularios', 'pesquisa',
  'pedido', 'pedidos', 'carrinho', 'loja', 'comercio', 'catalogo', 'produtos', 'produto', 'oferta',
  'ofertas', 'promocao', 'promocoes', 'desconto', 'descontos', 'atacado', 'varejo', 'revendedor',
  'revendedores', 'parceiro', 'parceiros',
  'estoque', 'almoxarifado', 'deposito', 'entrega', 'entregas', 'envio', 'logistica', 'transporte',
  'rastreamento', 'rastreio',
  'funcionario', 'funcionarios', 'colaborador', 'pessoal', 'rh', 'recrutamento', 'recrutamento',
  'vaga', 'vagas', 'carreira', 'carreiras', 'ferias', 'ponto',
  'acesso', 'entrar', 'cadastro', 'senha', 'usuario', 'perfil', 'configuracoes', 'mensagens',
  'notificacoes',
  'agendamento', 'agenda', 'reserva', 'reservas', 'consulta',
  'aluno', 'alunos', 'estudante', 'escola', 'curso', 'cursos', 'prova', 'provas', 'notas',
  'biblioteca', 'campus', 'matricula', 'ava',
  'saude', 'clinica', 'paciente', 'pacientes', 'farmacia', 'laboratorio', 'exames', 'exame',
  'receita', 'prontuario',
  'cidadao', 'prefeitura', 'municipio', 'governo', 'administracao', 'servicos', 'protocolo',
  'processo', 'processos', 'licitacao', 'licitacoes', 'ouvidoria',
  'empresa', 'companhia', 'sede', 'escritorio', 'filial', 'filiais', 'unidades', 'vendas', 'compras',
  'fornecedor', 'fornecedores',
  'crm', 'erp', 'intranet', 'extranet', 'portal', 'documentos', 'arquivo', 'projetos', 'contrato',
  'contratos', 'noticias', 'imprensa', 'eventos', 'boletim',
  'oficina', 'concessionaria', 'pecas', 'imoveis', 'viagem', 'viagens', 'hotel', 'restaurante',
  'cardapio', 'reservar',
];

/* Italian. */
const it = [
  'fattura', 'fatture', 'fatturazione', 'fatturaelettronica', 'contabilita', 'amministrazione',
  'finanza', 'busta', 'bustapaga', 'stipendio', 'tasse', 'iva', 'pagamento', 'pagamenti', 'incasso',
  'cassa', 'conto', 'conti', 'banca', 'bonifico', 'preventivo', 'ricevuta',
  'cliente', 'clienti', 'areaclienti', 'area-clienti', 'ilmioaccount', 'assistenza', 'supporto',
  'aiuto', 'contatti', 'ticket', 'reclamo', 'richiesta', 'richieste', 'modulo', 'moduli',
  'ordine', 'ordini', 'carrello', 'negozio', 'shop', 'catalogo', 'prodotti', 'prodotto', 'offerta',
  'offerte', 'promozione', 'promozioni', 'sconto', 'sconti', 'ingrosso', 'rivenditore',
  'rivenditori', 'partner',
  'magazzino', 'scorte', 'inventario', 'spedizione', 'spedizioni', 'consegna', 'logistica',
  'trasporto', 'tracciamento',
  'dipendente', 'dipendenti', 'personale', 'risorseumane', 'assunzioni', 'candidatura', 'carriera',
  'lavoro', 'ferie', 'presenze',
  'accesso', 'registrazione', 'password', 'utente', 'profilo', 'impostazioni', 'messaggi', 'notifiche',
  'appuntamento', 'appuntamenti', 'prenotazione', 'prenotazioni', 'agenda',
  'studente', 'studenti', 'scuola', 'corso', 'corsi', 'esame', 'esami', 'voti', 'biblioteca',
  'formazione', 'iscrizione',
  'salute', 'clinica', 'paziente', 'pazienti', 'farmacia', 'laboratorio', 'analisi', 'ricetta',
  'cittadino', 'comune', 'municipio', 'governo', 'amministrazionecomunale', 'servizi', 'pratica',
  'pratiche', 'protocollo', 'gara', 'gare', 'appalti',
  'azienda', 'societa', 'sede', 'ufficio', 'uffici', 'filiale', 'filiali', 'vendite', 'acquisti',
  'fornitore', 'fornitori',
  'crm', 'erp', 'intranet', 'extranet', 'portale', 'documenti', 'archivio', 'progetti', 'contratto',
  'contratti', 'notizie', 'stampa', 'eventi',
  'officina', 'concessionaria', 'ricambi', 'immobiliare', 'viaggio', 'viaggi', 'hotel', 'ristorante',
  'menu', 'prenota',
];

/* Dutch (NL / BE). */
const nl = [
  'factuur', 'facturen', 'facturatie', 'boekhouding', 'financien', 'loon', 'salaris', 'btw',
  'belasting', 'betaling', 'betalingen', 'kassa', 'rekening', 'bank', 'overschrijving', 'offerte',
  'bon',
  'klant', 'klanten', 'klantenportaal', 'mijnaccount', 'mijn-account', 'service', 'klantenservice',
  'ondersteuning', 'hulp', 'contact', 'ticket', 'klacht', 'aanvraag', 'aanvragen', 'formulier',
  'formulieren',
  'bestelling', 'bestellingen', 'winkelwagen', 'winkel', 'webshop', 'catalogus', 'producten',
  'product', 'aanbieding', 'aanbiedingen', 'korting', 'groothandel', 'dealer', 'dealers', 'partner',
  'partners',
  'voorraad', 'magazijn', 'levering', 'verzending', 'logistiek', 'transport', 'volgen',
  'medewerker', 'medewerkers', 'personeel', 'hr', 'sollicitatie', 'vacature', 'vacatures', 'carriere',
  'verlof',
  'inloggen', 'aanmelden', 'registratie', 'wachtwoord', 'gebruiker', 'profiel', 'instellingen',
  'berichten', 'meldingen',
  'afspraak', 'afspraken', 'reservering', 'reserveringen', 'agenda',
  'student', 'studenten', 'school', 'cursus', 'cursussen', 'examen', 'cijfers', 'bibliotheek',
  'gezondheid', 'kliniek', 'patient', 'patienten', 'apotheek', 'laboratorium', 'recept',
  'burger', 'gemeente', 'overheid', 'loket', 'aanvraagformulier', 'dossier', 'aanbesteding',
  'bedrijf', 'onderneming', 'kantoor', 'kantoren', 'vestiging', 'vestigingen', 'verkoop', 'inkoop',
  'leverancier', 'leveranciers',
  'crm', 'erp', 'intranet', 'extranet', 'portaal', 'documenten', 'archief', 'projecten', 'contract',
  'contracten', 'nieuws', 'pers', 'evenementen',
];

/* Polish (ASCII-folded). */
const pl = [
  'faktura', 'faktury', 'fakturowanie', 'ksiegowosc', 'finanse', 'wyplata', 'placa', 'podatek',
  'podatki', 'vat', 'platnosc', 'platnosci', 'kasa', 'konto', 'konta', 'bank', 'przelew', 'oferta',
  'oferty', 'rachunek', 'paragon',
  'klient', 'klienci', 'panelklienta', 'mojekonto', 'moje-konto', 'obsluga', 'wsparcie', 'pomoc',
  'kontakt', 'zgloszenie', 'zgloszenia', 'reklamacja', 'wniosek', 'wnioski', 'formularz',
  'zamowienie', 'zamowienia', 'koszyk', 'sklep', 'katalog', 'produkty', 'produkt', 'promocja',
  'promocje', 'rabat', 'hurt', 'dealer', 'partner', 'partnerzy',
  'magazyn', 'stan', 'dostawa', 'dostawy', 'wysylka', 'logistyka', 'transport', 'sledzenie',
  'pracownik', 'pracownicy', 'kadry', 'hr', 'rekrutacja', 'praca', 'kariera', 'urlop',
  'logowanie', 'rejestracja', 'haslo', 'uzytkownik', 'profil', 'ustawienia', 'wiadomosci',
  'powiadomienia',
  'rezerwacja', 'rezerwacje', 'wizyta', 'wizyty', 'kalendarz', 'terminarz',
  'student', 'studenci', 'uczen', 'szkola', 'kurs', 'kursy', 'egzamin', 'oceny', 'biblioteka',
  'zdrowie', 'klinika', 'pacjent', 'pacjenci', 'apteka', 'laboratorium', 'recepta',
  'obywatel', 'gmina', 'urzad', 'administracja', 'uslugi', 'sprawa', 'przetarg',
  'przetargi',
  'firma', 'spolka', 'siedziba', 'biuro', 'oddzial', 'oddzialy', 'sprzedaz', 'zakupy', 'dostawca',
  'dostawcy',
  'crm', 'erp', 'intranet', 'extranet', 'portal', 'dokumenty', 'archiwum', 'projekty', 'umowa',
  'umowy', 'aktualnosci', 'prasa', 'wydarzenia',
];

/* Russian / CIS (Latin transliteration). */
const ru = [
  'schet', 'scheta', 'schetfaktura', 'buhgalteriya', 'finansy', 'zarplata', 'nalog', 'nalogi', 'nds',
  'oplata', 'platezh', 'platezhi', 'kassa', 'bank', 'perevod', 'smeta', 'kvitanciya', 'dokument',
  'klient', 'klienty', 'lichnyjkabinet', 'kabinet', 'lk', 'moyschet', 'podderzhka', 'pomosch',
  'kontakt', 'kontakty', 'zayavka', 'zayavki', 'obraschenie', 'zhaloba', 'anketa', 'forma',
  'zakaz', 'zakazy', 'korzina', 'magazin', 'katalog', 'tovary', 'tovar', 'aktsiya', 'aktsii', 'skidka',
  'skidki', 'opt', 'diler', 'dilery', 'partner', 'partnery',
  'sklad', 'ostatki', 'dostavka', 'otgruzka', 'logistika', 'transport', 'otslezhivanie',
  'sotrudnik', 'sotrudniki', 'personal', 'kadry', 'hr', 'vakansii', 'rabota', 'karyera', 'otpusk',
  'vhod', 'registraciya', 'parol', 'polzovatel', 'profil', 'nastrojki', 'soobscheniya',
  'uvedomleniya',
  'zapis', 'zapisi', 'bronirovanie', 'raspisanie', 'kalendar',
  'student', 'studenty', 'shkola', 'kurs', 'kursy', 'ekzamen', 'ocenki', 'biblioteka', 'obuchenie',
  'zdorovie', 'klinika', 'pacient', 'pacienty', 'apteka', 'laboratoriya', 'recept', 'priem',
  'grazhdanin', 'gorod', 'administraciya', 'gosuslugi', 'uslugi', 'obraschenie', 'zakupki', 'tender',
  'tendery',
  'kompaniya', 'firma', 'ofis', 'ofisy', 'filial', 'filialy', 'prodazhi', 'postavschik',
  'postavschiki',
  'crm', 'erp', 'intranet', 'extranet', 'portal', 'dokumenty', 'arhiv', 'proekty', 'dogovor',
  'dogovory', 'novosti', 'pressa', 'meropriyatiya',
];

/* Arabic markets (Latin transliteration; SA / AE / EG …). */
const ar = [
  'fatura', 'fawatir', 'fatoora', 'muhasaba', 'maliya', 'rawatib', 'ratib', 'dareeba', 'darebah',
  'vat', 'dafaa', 'madfooat', 'sandooq', 'hisab', 'hisabat', 'bank', 'tahweel', 'aroudh', 'wasl',
  'zabon', 'zaboon', 'zabaen', 'ameel', 'omala', 'hisabi', 'daam', 'musaada', 'ittisal', 'tawasul',
  'tathkara', 'shakwa', 'talab', 'talabat', 'namudaj', 'istibyan',
  'talabiya', 'salla', 'matjar', 'mataajir', 'soog', 'catalog', 'muntajat', 'muntaj', 'ard', 'orood',
  'khasm', 'tanzilat', 'jumla', 'wakil', 'wukala', 'shareek', 'shuraka', 'fare', 'furoo',
  'makhzan', 'makhazin', 'shahn', 'tawseel', 'logistiyat', 'naql', 'tatabu',
  'muwazzaf', 'muwazzafin', 'muwarad', 'mawarid', 'tawzeef', 'wazaif', 'wazifa', 'ijaza',
  'dukhool', 'tasjeel', 'password', 'mustakhdim', 'idadat', 'rasail', 'tanbihat',
  'mawid', 'mawaid', 'hajz', 'jadwal',
  'talib', 'tullab', 'madrasa', 'jamia', 'dawra', 'dawrat', 'imtihan', 'darajat', 'maktaba', 'taalim',
  'sihha', 'seha', 'ayada', 'marid', 'marda', 'saydaliya', 'mukhtabar', 'tahaleel', 'wasfa',
  'muwatin', 'baladiya', 'hukooma', 'khadamat', 'khidma', 'muamala', 'muamalat', 'monaqasa',
  'monaqasat',
  'sharika', 'maqar', 'maktab', 'makatib', 'far3', 'mabee3at', 'mushtarayat',
  'crm', 'erp', 'intranet', 'extranet', 'bawaba', 'wathaeq', 'arshif', 'mashari3', 'aqd', 'oqood',
  'akhbar', 'sahafa', 'faaliyat',
];

/* Japanese (Hepburn romaji) — modest, credible set. */
const ja = [
  'seikyu', 'seikyusho', 'keiri', 'kaikei', 'zaimu', 'kyuyo', 'zeikin', 'shiharai', 'nyukin', 'reji',
  'ginko', 'furikomi', 'mitsumori', 'ryoshusho',
  'kokyaku', 'kaiin', 'mypage', 'toiawase', 'renraku', 'moushikomi',
  'chumon', 'kago', 'shoppu', 'tenpo', 'katarogu', 'shohin', 'ryokin', 'wari', 'kyanpen',
  'zaiko', 'soko', 'haiso', 'hasso', 'butsuryu', 'unso', 'tsuiseki',
  'shain', 'jinji', 'saiyo', 'kyujin', 'shigoto', 'kyuka',
  'login', 'toroku', 'password', 'settei', 'tsuchi',
  'yoyaku', 'yotei', 'karenda',
  'gakusei', 'gakko', 'koza', 'shiken', 'seiseki', 'toshokan', 'manabi',
  'kenko', 'byoin', 'kanja', 'yakkyoku', 'kensa',
  'shimin', 'shiyakusho', 'gyosei', 'sabisu', 'shinsei', 'nyusatsu',
  'kaisha', 'honsha', 'shiten', 'eigyo', 'shiire', 'torihikisaki',
  'crm', 'erp', 'intranet', 'portal', 'bunsho', 'shiryo', 'purojekuto', 'keiyaku', 'oshirase',
];

/* Chinese (Hanyu Pinyin, no tones) — modest, credible set. */
const zh = [
  'fapiao', 'kaipiao', 'caiwu', 'kuaiji', 'gongzi', 'shuiwu', 'zhifu', 'shoukuan', 'shouyin',
  'yinhang', 'zhuanzhang', 'baojia', 'shouju',
  'kehu', 'huiyuan', 'wodezhanghu', 'zhichi', 'kefu', 'bangzhu', 'lianxi', 'gongdan', 'tousu',
  'shenqing', 'biaodan',
  'dingdan', 'gouwuche', 'shangdian', 'mendian', 'chanpin', 'jiage', 'youhui', 'cuxiao', 'zhekou',
  'pifa', 'jingxiaoshang', 'huoban', 'fendian',
  'kucun', 'cangku', 'peisong', 'fahuo', 'wuliu', 'yunshu', 'genzong',
  'yuangong', 'renshi', 'zhaopin', 'zhiwei', 'gongzuo', 'xiujia',
  'denglu', 'zhuce', 'mima', 'yonghu', 'gerenziliao', 'shezhi', 'xiaoxi', 'tongzhi',
  'yuyue', 'richeng', 'rili',
  'xuesheng', 'xuexiao', 'kecheng', 'kaoshi', 'chengji', 'tushuguan', 'jiaoyu',
  'jiankang', 'yiyuan', 'huanzhe', 'yaodian', 'huayan',
  'shimin', 'zhengfu', 'fuwu', 'banli', 'zhaobiao',
  'gongsi', 'zongbu', 'fenbu', 'xiaoshou', 'caigou', 'gongyingshang',
  'crm', 'erp', 'neiwang', 'menhu', 'wendang', 'ziliao', 'xiangmu', 'hetong', 'gonggao',
];

/**
 * Locale packs keyed by ISO country/language code. Each value is a curated,
 * ASCII-folded label list; the builder validates, dedupes and writes each to
 * assets/data/locale/<key>.txt.
 * @type {Record<string,string[]>}
 */
export const LOCALE_PACKS = { tr, de, fr, es, pt, it, nl, pl, ru, ar, ja, zh };

/**
 * Short provenance note per pack, embedded in the manifest / data README.
 * All packs are original curation for this project (MIT), ASCII-folded.
 */
export const LOCALE_NOTE =
  'Original curation for DomainScope (MIT). ASCII-folded generic business / public-service / ' +
  'e-commerce / accounting / e-government vocabulary for the market; never sourced from any ' +
  'single organisation\'s DNS zone.';
