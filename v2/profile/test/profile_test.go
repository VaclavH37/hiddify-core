package test

import (
	"fmt"
	"testing"

	"github.com/hiddify/hiddify-core/v2/profile"
	"github.com/sagernet/sing-box/experimental/libbox"
)

// Quarantined by this fork. Upstream test, kept verbatim below so a future
// upstream change to it still merges cleanly.
//
// It fetches a V2Ray-format WARP subscription and expects the parsed title to be
// "🔥 WARP 🔥". It cannot pass here, for two independent reasons:
//
//  1. The V2Ray parser is gone. Fork commit 9a5601d ("Remove Ray2Sing") deleted
//     the ray2sing.Ray2SingboxOptions branch from v2/config/parser.go, so parsing
//     falls through to Clash, which cannot read that format. The failure surfaces
//     as "unable to determine config format" — which is the correct behaviour
//     here, not a defect. TestV2RayFormatIsNotParsed in v2/config pins that
//     intent offline.
//  2. WARP is removed from this fork entirely.
//
// It also reaches raw.githubusercontent.com at test time, which makes it unfit
// for a validation gate regardless of the above.
//
// Skipped rather than deleted so that the reason travels with the code: if the
// V2Ray parser is ever reinstated, this is where the question resurfaces.
// Recorded as K2 in docs/upstream/BASELINE.md.
func TestAddByContent(t *testing.T) {
	t.Skip("upstream test for the V2Ray/ray2sing parser and WARP, both removed " +
		"from this fork (see 9a5601d); also requires network access")

	ctx := libbox.BaseContext(nil)
	entity, err := profile.AddByUrl(ctx, "https://raw.githubusercontent.com/hiddify/hiddify-next/refs/heads/main/test.configs/warp", "", false)
	if err != nil {
		t.Fatalf("expected no error, but got: %v", err)
	}
	fmt.Printf("entity: %v\n", entity)
	// Check if the content has been added correctly
	profileTitle := entity.Name
	expectedTitle := "🔥 WARP 🔥" // The Base64 decoded title
	if profileTitle != expectedTitle {
		t.Errorf("expected profile title to be %v, got %v", expectedTitle, profileTitle)
	}

	// Check subscription userinfo
	userInfo := entity.SubInfo
	if userInfo.Upload != 0 || userInfo.Download != 0 || userInfo.Total != 10737418240000000 || userInfo.Expire != 2546249531 {
		t.Errorf("subscription userinfo not parsed correctly, got: %v", userInfo)
	}

	// Check URLs
	supportURL := entity.SubInfo.SupportUrl
	if supportURL != "https://t.me/hiddify" {
		t.Errorf("expected support URL to be https://t.me/hiddify, got %v", supportURL)
	}

	profileWebPageURL := entity.SubInfo.WebPageUrl
	if profileWebPageURL != "https://hiddify.com" {
		t.Errorf("expected profile web page URL to be https://hiddify.com, got %v", profileWebPageURL)
	}
	profile.DeleteById(entity.Id)
	// You can further assert individual fields of warp configurations
}
