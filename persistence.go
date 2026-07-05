package gonetwork

// ---------------------------------------------------------------------------
// C-4: bbolt block store — durable block persistence
//
// BlockStore wraps a bbolt (BoltDB) database and provides two operations:
//
//   - SaveBlock(b *Block)               — appends or overwrites a block by index.
//   - LoadBlocks(bc *Blockchain) error  — reads all stored blocks into bc.Blocks,
//                                         preserving their original order.
//
// The database uses a single bucket ("blocks") keyed by the block index encoded
// as a zero-padded 10-digit decimal string so that BoltDB's byte-sorted iteration
// yields blocks in chain order.
//
// Usage (in cmd/api/main.go):
//
//	store, err := gonetwork.OpenBlockStore("greenhouse.db")
//	if err != nil { log.Fatal(err) }
//	defer store.Close()
//	if err := store.LoadBlocks(bc); err != nil { log.Printf("load: %v", err) }
//	bc.BlockStore = store  // SealBlock calls store.SaveBlock after every seal
// ---------------------------------------------------------------------------

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log"

	bolt "go.etcd.io/bbolt"
)

const (
	blocksBucket            = "blocks"
	stateBucket             = "state"
	confirmedPaymentsBucket = "confirmed_payments"
	delegatesBucket         = "delegates"
	reportingOutboxBucket   = "reporting_outbox"
	amlScreeningLogBucket   = "aml_screening_log"
	closedSARBucket         = "closed_sars"
	closedSTORBucket        = "closed_stors"
)

// BlockStore wraps a bbolt database for block persistence.
type BlockStore struct {
	db *bolt.DB
}

// OpenBlockStore opens (or creates) a bbolt database at the given file path and
// ensures the "blocks" bucket exists.
func OpenBlockStore(path string) (*BlockStore, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("OpenBlockStore: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(blocksBucket)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(stateBucket)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(confirmedPaymentsBucket)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(delegatesBucket)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(reportingOutboxBucket)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(amlScreeningLogBucket)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(closedSARBucket)); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists([]byte(closedSTORBucket))
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("OpenBlockStore: bucket init: %w", err)
	}
	return &BlockStore{db: db}, nil
}

// SaveToReportingOutbox serialises report as JSON and stores it in the
// "reporting_outbox" bucket under report.ID. Called when NCA/ARM submission
// fails so the report can be retried by the background outbox goroutine.
func (bs *BlockStore) SaveToReportingOutbox(report *RegulatoryReport) error {
	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("BlockStore.SaveToReportingOutbox: marshal: %w", err)
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(reportingOutboxBucket)).Put([]byte(report.ID), data)
	})
}

// SaveConfirmedPayment serialises a payment confirmation and stores it in the
// durable confirmation ledger. The ledger keeps historical confirmations even
// after the in-memory cache prunes old entries for retention.
func (bs *BlockStore) SaveConfirmedPayment(conf *PaymentConfirmation) error {
	if conf == nil {
		return fmt.Errorf("BlockStore.SaveConfirmedPayment: confirmation is nil")
	}
	data, err := json.Marshal(conf)
	if err != nil {
		return fmt.Errorf("BlockStore.SaveConfirmedPayment: marshal: %w", err)
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(confirmedPaymentsBucket)).Put([]byte(conf.InstructionID), data)
	})
}

// LoadConfirmedPayment retrieves a single confirmation from the durable
// confirmation ledger. It returns (nil, false, nil) when no entry exists.
func (bs *BlockStore) LoadConfirmedPayment(instructionID string) (*PaymentConfirmation, bool, error) {
	var conf PaymentConfirmation
	found := false
	err := bs.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(confirmedPaymentsBucket))
		if b == nil {
			return nil
		}
		data := b.Get([]byte(instructionID))
		if data == nil {
			return nil
		}
		if err := json.Unmarshal(data, &conf); err != nil {
			return fmt.Errorf("BlockStore.LoadConfirmedPayment: unmarshal: %w", err)
		}
		found = true
		return nil
	})
	if err != nil || !found {
		return nil, found, err
	}
	return &conf, true, nil
}

// LoadReportingOutbox reads all pending reports from the outbox bucket.
func (bs *BlockStore) LoadReportingOutbox() ([]*RegulatoryReport, error) {
	var reports []*RegulatoryReport
	err := bs.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(reportingOutboxBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var r RegulatoryReport
			if err := json.Unmarshal(v, &r); err != nil {
				log.Printf("BlockStore.LoadReportingOutbox: skipping malformed entry key=%s: %v", k, err)
				return nil
			}
			reports = append(reports, &r)
			return nil
		})
	})
	return reports, err
}

// DeleteFromReportingOutbox removes the report with the given ID from the
// outbox after a successful NCA/ARM submission.
func (bs *BlockStore) DeleteFromReportingOutbox(reportID string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(reportingOutboxBucket))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(reportID))
	})
}

// SaveAMLScreeningLog persists a durable AML screening decision record for
// compliance audit trails (Phase 1.6). Append-only: entries are never
// overwritten or deleted, keyed by entry.ID.
func (bs *BlockStore) SaveAMLScreeningLog(entry *AMLScreeningLogEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("BlockStore.SaveAMLScreeningLog: marshal: %w", err)
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(amlScreeningLogBucket)).Put([]byte(entry.ID), data)
	})
}

// LoadAMLScreeningLog returns all persisted AML screening log entries, for
// compliance review or regulator requests.
func (bs *BlockStore) LoadAMLScreeningLog() ([]*AMLScreeningLogEntry, error) {
	var entries []*AMLScreeningLogEntry
	err := bs.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(amlScreeningLogBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var e AMLScreeningLogEntry
			if err := json.Unmarshal(v, &e); err != nil {
				log.Printf("BlockStore.LoadAMLScreeningLog: skipping malformed entry key=%s: %v", k, err)
				return nil
			}
			entries = append(entries, &e)
			return nil
		})
	})
	return entries, err
}

// SaveClosedSAR archives a resolved SARDraft to the durable "closed_sars"
// bucket (MAR/JMLSG retention requirements). Called when a SAR transitions
// out of PendingSARs via resolution so the record survives restarts even
// after it is removed from the live pending map.
func (bs *BlockStore) SaveClosedSAR(sar *SARDraft) error {
	data, err := json.Marshal(sar)
	if err != nil {
		return fmt.Errorf("BlockStore.SaveClosedSAR: marshal: %w", err)
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(closedSARBucket)).Put([]byte(sar.ID), data)
	})
}

// LoadClosedSARs returns all archived (resolved) SAR drafts.
func (bs *BlockStore) LoadClosedSARs() ([]*SARDraft, error) {
	var out []*SARDraft
	err := bs.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(closedSARBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var sar SARDraft
			if err := json.Unmarshal(v, &sar); err != nil {
				log.Printf("BlockStore.LoadClosedSARs: skipping malformed entry key=%s: %v", k, err)
				return nil
			}
			out = append(out, &sar)
			return nil
		})
	})
	return out, err
}

// SaveClosedSTOR archives a resolved STORDraft to the durable "closed_stors"
// bucket (MAR Article 16 retention requirements).
func (bs *BlockStore) SaveClosedSTOR(stor *STORDraft) error {
	data, err := json.Marshal(stor)
	if err != nil {
		return fmt.Errorf("BlockStore.SaveClosedSTOR: marshal: %w", err)
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(closedSTORBucket)).Put([]byte(stor.ID), data)
	})
}

// LoadClosedSTORs returns all archived (resolved) STOR drafts.
func (bs *BlockStore) LoadClosedSTORs() ([]*STORDraft, error) {
	var out []*STORDraft
	err := bs.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(closedSTORBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var stor STORDraft
			if err := json.Unmarshal(v, &stor); err != nil {
				log.Printf("BlockStore.LoadClosedSTORs: skipping malformed entry key=%s: %v", k, err)
				return nil
			}
			out = append(out, &stor)
			return nil
		})
	})
	return out, err
}

// Close cleanly shuts down the bbolt database.
func (bs *BlockStore) Close() error {
	return bs.db.Close()
}

// SaveBlock serialises b as JSON and writes it to the "blocks" bucket under the
// key fmt.Sprintf("%010d", b.Index). Overwrites any existing entry at that index.
func (bs *BlockStore) SaveBlock(b *Block) error {
	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("BlockStore.SaveBlock: marshal: %w", err)
	}
	key := []byte(keyForIndex(b.Index))
	return bs.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(blocksBucket)).Put(key, data)
	})
}

// Backup writes a consistent BBolt snapshot to w.
// Safe to call concurrently with SaveBlock because it uses a read-only
// transaction pinned to a consistent view of the database.
func (bs *BlockStore) Backup(w io.Writer) error {
	if bs == nil || bs.db == nil {
		return fmt.Errorf("BlockStore.Backup: store is not initialised")
	}
	return bs.db.View(func(tx *bolt.Tx) error {
		_, err := tx.WriteTo(w)
		return err
	})
}

// LoadBlocks reads all blocks from the database in index order and appends them
// to bc.Blocks. It does NOT acquire bc.Mu — callers must ensure exclusive access
// (e.g. call only from Start() before serving requests).
func (bs *BlockStore) LoadBlocks(bc *Blockchain) error {
	return bs.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		if b == nil {
			return nil // empty store — first start
		}
		return b.ForEach(func(k, v []byte) error {
			var blk Block
			if err := json.Unmarshal(v, &blk); err != nil {
				log.Printf("BlockStore.LoadBlocks: skipping malformed block key=%s: %v", k, err)
				return nil
			}
			bc.Blocks = append(bc.Blocks, blk)
			return nil
		})
	})
}

// BlockCount returns the number of blocks currently stored.
func (bs *BlockStore) BlockCount() (int, error) {
	var n int
	err := bs.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		if b != nil {
			n = b.Stats().KeyN
		}
		return nil
	})
	return n, err
}

// keyForIndex returns the zero-padded decimal key string for a block index.
// Uses a 10-digit zero-padded format so BBolt's byte-ordered iteration yields
// blocks in ascending chain order. Must match the format used by SaveBlock.
func keyForIndex(index int) string {
	return fmt.Sprintf("%010d", index)
}

// stateSnapshot is the on-disk representation of the key in-memory chain maps.
// LastAppliedBlock records the highest block index whose state changes are
// reflected in this snapshot, enabling catch-up replay on startup.
type stateSnapshot struct {
	Assets                 map[string]*Asset                 `json:"assets"`
	Holdings               map[string]*AssetHolding          `json:"holdings"`
	Credentials            map[string]*CredentialAttestation `json:"credentials"`
	WalletSequences        map[string]int64                  `json:"wallet_sequences"`
	ConfirmedPayments      map[string]*PaymentConfirmation   `json:"confirmed_payments,omitempty"`
	PendingSARs            map[string]*SARDraft              `json:"pending_sars,omitempty"`
	PendingSTORs           map[string]*STORDraft             `json:"pending_stors,omitempty"`
	InsiderLists           map[string]*InsiderList           `json:"insider_lists,omitempty"`
	RegulatoryReports      []*RegulatoryReport               `json:"regulatory_reports,omitempty"`
	ProspectusExemptions   map[string]*ProspectusExemption   `json:"prospectus_exemptions,omitempty"`
	SuitabilityAssessments map[string]*SuitabilityAssessment `json:"suitability_assessments,omitempty"`
	JurisdictionRules      map[string]*JurisdictionRule      `json:"jurisdiction_rules,omitempty"`
	LegalDocAmendments     map[string][]*LegalDocAmendment   `json:"legal_doc_amendments,omitempty"`
	Claims                 map[string][]*Claim               `json:"claims,omitempty"`
	TrustedIssuers         *TrustedIssuersRegistry           `json:"trusted_issuers,omitempty"`
	LastAppliedBlock       int                               `json:"last_applied_block"`
}

// SaveState persists the blockchain's key in-memory maps to the "state" bucket.
// It is called by SealBlock and finalizeBlock while bc.Mu is held, so all reads
// of bc fields are safe. lastBlockIndex must be the index of the block whose
// applyBlockState has just completed.
func (bs *BlockStore) SaveState(bc *Blockchain, lastBlockIndex int) error {
	snap := stateSnapshot{
		Assets:                 bc.Assets,
		Holdings:               bc.Holdings,
		Credentials:            bc.Credentials,
		WalletSequences:        bc.WalletSequences,
		ConfirmedPayments:      bc.ConfirmedPayments,
		PendingSARs:            bc.PendingSARs,
		PendingSTORs:           bc.PendingSTORs,
		InsiderLists:           bc.InsiderLists,
		RegulatoryReports:      bc.RegulatoryReports,
		ProspectusExemptions:   bc.ProspectusExemptions,
		SuitabilityAssessments: bc.SuitabilityAssessments,
		JurisdictionRules:      bc.JurisdictionRules,
		LegalDocAmendments:     bc.LegalDocAmendments,
		Claims:                 bc.Claims,
		TrustedIssuers:         bc.TrustedIssuers,
		LastAppliedBlock:       lastBlockIndex,
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("BlockStore.SaveState: marshal: %w", err)
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(stateBucket)).Put([]byte("snapshot"), data)
	})
}

// LoadState reads the state snapshot from the "state" bucket and restores
// bc.Assets, bc.Holdings, bc.Credentials, and bc.WalletSequences. It returns
// the LastAppliedBlock index recorded in the snapshot, or -1 if no snapshot
// exists (first run). The caller uses this value to determine whether catch-up
// replay is needed for blocks newer than the snapshot.
func (bs *BlockStore) LoadState(bc *Blockchain) (int, error) {
	lastApplied := -1
	err := bs.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(stateBucket))
		if b == nil {
			return nil
		}
		data := b.Get([]byte("snapshot"))
		if data == nil {
			return nil
		}
		var snap stateSnapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			return fmt.Errorf("BlockStore.LoadState: unmarshal: %w", err)
		}
		if snap.Assets != nil {
			bc.Assets = snap.Assets
		}
		if snap.Holdings != nil {
			bc.Holdings = snap.Holdings
		}
		if snap.Credentials != nil {
			bc.Credentials = snap.Credentials
		}
		if snap.WalletSequences != nil {
			bc.WalletSequences = snap.WalletSequences
		}
		if snap.ConfirmedPayments != nil {
			bc.ConfirmedPayments = snap.ConfirmedPayments
		}
		if snap.PendingSARs != nil {
			bc.PendingSARs = snap.PendingSARs
		}
		if snap.PendingSTORs != nil {
			bc.PendingSTORs = snap.PendingSTORs
		}
		if snap.InsiderLists != nil {
			bc.InsiderLists = snap.InsiderLists
		}
		if snap.RegulatoryReports != nil {
			bc.RegulatoryReports = snap.RegulatoryReports
		}
		if snap.ProspectusExemptions != nil {
			bc.ProspectusExemptions = snap.ProspectusExemptions
		}
		if snap.SuitabilityAssessments != nil {
			bc.SuitabilityAssessments = snap.SuitabilityAssessments
		}
		if snap.JurisdictionRules != nil {
			bc.JurisdictionRules = snap.JurisdictionRules
		}
		if snap.LegalDocAmendments != nil {
			bc.LegalDocAmendments = snap.LegalDocAmendments
		}
		if snap.Claims != nil {
			bc.Claims = snap.Claims
		}
		if snap.TrustedIssuers != nil {
			bc.TrustedIssuers = snap.TrustedIssuers
		}
		lastApplied = snap.LastAppliedBlock
		return nil
	})
	return lastApplied, err
}

// ---------------------------------------------------------------------------
// Delegate set persistence (Item 10)
//
// persistedDelegate is the on-disk representation of a Node. Only the identity
// and cryptographic fields are stored; runtime fields (Inbox, VotingStrategy,
// Blockchain, viewChangeRequests) are excluded and must be re-wired after load.
//
// Security note: PrivateKey is included so that delegates can sign blocks after
// restart. In production deployments with HSM/KMS integration (Item 7), the
// private-key field should be omitted and keys loaded from the secure store.
// ---------------------------------------------------------------------------

type persistedDelegate struct {
	ID         string             `json:"id"`
	P2PPeerID  string             `json:"p2p_peer_id,omitempty"`
	IsDelegate bool               `json:"is_delegate"`
	Stake      int                `json:"stake"`
	Votes      int                `json:"votes"`
	PublicKey  ed25519.PublicKey  `json:"public_key,omitempty"`
	PrivateKey ed25519.PrivateKey `json:"private_key,omitempty"`
}

// SaveDelegates serialises the active delegate set to the "delegates" bucket
// under the key "active". It is called by VoteForDelegates after every
// successful election so that the active set survives a node restart.
// Only identity and key fields are stored; runtime state is re-initialised
// on load by LoadDelegates.
func (bs *BlockStore) SaveDelegates(delegates []Node) error {
	pds := make([]persistedDelegate, len(delegates))
	for i, n := range delegates {
		pds[i] = persistedDelegate{
			ID:         n.ID,
			P2PPeerID:  n.P2PPeerID,
			IsDelegate: n.IsDelegate,
			Stake:      n.Stake,
			Votes:      n.Votes,
			PublicKey:  n.PublicKey,
			PrivateKey: n.PrivateKey,
		}
	}
	data, err := json.Marshal(pds)
	if err != nil {
		return fmt.Errorf("BlockStore.SaveDelegates: marshal: %w", err)
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(delegatesBucket)).Put([]byte("active"), data)
	})
}

// LoadDelegates reads the saved delegate set from the "delegates" bucket and
// assigns it to bc.Delegates. Runtime fields (Inbox, VotingStrategy,
// Blockchain, viewChangeRequests) are re-initialised to defaults so the
// delegates are immediately usable for consensus after load.
// Returns nil (no error) if no delegate set has been saved yet.
func (bs *BlockStore) LoadDelegates(bc *Blockchain) error {
	return bs.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(delegatesBucket))
		if b == nil {
			return nil // bucket not yet created — no delegates saved
		}
		data := b.Get([]byte("active"))
		if data == nil {
			return nil // no saved set yet
		}
		var pds []persistedDelegate
		if err := json.Unmarshal(data, &pds); err != nil {
			return fmt.Errorf("BlockStore.LoadDelegates: unmarshal: %w", err)
		}
		nodes := make([]Node, len(pds))
		for i, pd := range pds {
			nodes[i] = Node{
				ID:                 pd.ID,
				P2PPeerID:          pd.P2PPeerID,
				IsDelegate:         pd.IsDelegate,
				Stake:              pd.Stake,
				Votes:              pd.Votes,
				PublicKey:          pd.PublicKey,
				PrivateKey:         pd.PrivateKey,
				Inbox:              make(chan Message, 100),
				Blockchain:         bc,
				viewChangeRequests: make(map[int]int),
			}
		}
		bc.Mu.Lock()
		bc.Delegates = nodes
		bc.Mu.Unlock()
		return nil
	})
}
