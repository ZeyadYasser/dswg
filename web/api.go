package web

import (
	"github.com/gin-gonic/gin"
	"github.com/zeyadyasser/dswg"
)

type APIController struct {
	DB	dswg.DB
	Client dswg.Client
}

func (api *APIController) GetLink(c *gin.Context) {
	link, err := api.DB.GetLink(c.Param("link_name"))
	if err != nil {
		c.JSON(404, gin.H{
			"error": err.Error(),
		})
	} else {
		c.JSON(200, link)
	}
}

func (api *APIController) GetLinks(c *gin.Context) {
	links, err := api.DB.GetLinks()
	if err != nil {
		c.JSON(500, gin.H{
			"error": err.Error(),
		})
	} else {
		c.JSON(200, links)
	}
}

func (api *APIController) AddLink(c *gin.Context) {
	var link dswg.Link

	err := c.BindJSON(&link)
	if err != nil {
		return
	}

	err = api.Client.AddLink(link)
	if err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"error": err.Error(),
		})
	} else {
		c.JSON(200, gin.H{
			"success": true,
		})
	}
}

func (api *APIController) RemoveLink(c *gin.Context) {
	err := api.Client.RemoveLink(c.Param("link_name"))
	if err != nil {
		c.JSON(404, gin.H{
			"error": err.Error(),
		})
	} else {
		c.JSON(200, gin.H{
			"success": true,
		})
	}
}

func (api *APIController) UpdateLink(c *gin.Context) {
	link, err := api.DB.GetLink(c.Param("link_name"))
	if err != nil {
		c.JSON(404, gin.H{
			"error": err.Error(),
		})
		return
	}

	err = c.BindJSON(link)
	if err != nil {
		return
	}

	err = api.Client.UpdateLink(c.Param("link_name"), *link)
	if err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"error": err.Error(),
		})
	} else {
		c.JSON(200, gin.H{
			"success": true,
		})
	}
}

func (api *APIController) GetPeer(c *gin.Context) {
	peer, err := api.DB.GetPeer(c.Param("link_name"), c.Param("peer_name"))
	if err != nil {
		c.JSON(404, gin.H{
			"error": err.Error(),
		})
	} else {
		c.JSON(200, peer)
	}
}

func (api *APIController) GetPeers(c *gin.Context) {
	peers, err := api.DB.GetLinkPeers(c.Param("link_name"))
	if err != nil {
		c.JSON(500, gin.H{
			"error": err.Error(),
		})
	} else {
		c.JSON(200, peers)
	}
}

func (api *APIController) AddPeer(c *gin.Context) {
	var peer dswg.Peer

	err := c.BindJSON(&peer)
	if err != nil {
		return
	}

	err = api.Client.AddPeer(c.Param("link_name"), peer)
	if err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"error": err.Error(),
		})
	} else {
		c.JSON(200, gin.H{
			"success": true,
		})
	}
}

func (api *APIController) RemovePeer(c *gin.Context) {
	err := api.Client.RemovePeer(c.Param("link_name"), c.Param("peer_name"))
	if err != nil {
		c.JSON(404, gin.H{
			"error": err.Error(),
		})
	} else {
		c.JSON(200, gin.H{
			"success": true,
		})
	}
}

func (api *APIController) UpdatePeer(c *gin.Context) {
	peer, err := api.DB.GetPeer(c.Param("link_name"), c.Param("peer_name"))
	if err != nil {
		c.JSON(404, gin.H{
			"error": err.Error(),
		})
		return
	}

	err = c.BindJSON(peer)
	if err != nil {
		return
	}

	err = api.Client.UpdatePeer(c.Param("link_name"), c.Param("peer_name"), *peer)
	if err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"error": err.Error(),
		})
	} else {
		c.JSON(200, gin.H{
			"success": true,
		})
	}
}