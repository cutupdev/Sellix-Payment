import { Request, Response, Router } from "express";
import { check, validationResult } from "express-validator";
import { authMiddleware } from "../../middleware";
import ApiKeyModel from "../../model/ApiKeyModel";
import validateKey from "../../utils/validateKey";
import keyGen from "../../utils/keyGen";

// Create a new instance of the Express Router
const ApiKeyRouter = Router();

// @route    Post api/apiKey/healthCheck
// @desc     Health Check api key 
// @access   Private
ApiKeyRouter.post(
    '/healthCheck',
    check("apiKey", "Apikey is required").notEmpty(),
    authMiddleware,
    async (req: Request, res: Response) => {
        try {
            const apiKey = req.body.apiKey;
            await validateKey(apiKey, req, res);
        } catch (err) {
            console.log("apikey health check error ===> ", err);
            return res.status(500).json({ error: "An error occurred while checking health of apikey." });
        }
    }
)

// @route    Post api/apiKey/generate
// @desc     Generate api key
// @access   Private
ApiKeyRouter.post(
    '/generate',
    check("subscriptionId", "SubscriptionId is required").notEmpty(),
    authMiddleware,
    async (req: Request, res: Response) => {
        try {
            const result = await keyGen(1);
            const newIp = new ApiKeyModel({
                subscriptionId: req.body.subscriptionId,
                apiKey: result
            })
            await newIp.save();
            return res.json({ success: true, key: result });
        } catch (err) {
            console.log("Key generate error ===> ", err);
            return res.status(500).json({ success: false, error: "An error occurred while generating new apikey." });
        }
    }
)

// @route    Post api/apiKey/update
// @desc     Update api key
// @access   Private
ApiKeyRouter.post(
    '/update',
    check("apiKeyId", "Api key Id is required").notEmpty(),
    authMiddleware,
    async (req: Request, res: Response) => {
        try {
            const result = await keyGen(1);
            const newData = await ApiKeyModel.findOneAndUpdate(
                { _id: req.body.apiKeyId },
                { apiKey: result },
                { new: true }
            )
            return res.json({ success: true, data: newData });
        } catch (err) {
            console.log("Key generate error ===> ", err);
            return res.status(500).json({ success: false, error: "An error occurred while updating new apikey." });
        }
    }
)

// @route    Post api/apiKey/delete/:id
// @desc     delete api key
// @access   Private
ApiKeyRouter.post(
    '/delete/:id',
    check("apiKeyId", "Api key Id is required").notEmpty(),
    authMiddleware,
    async (req: Request, res: Response) => {
        const id = req.params.id;
        try {
            const data = await ApiKeyModel.findById(id);
            if (!data) {
                return res.status(400).json({ success: false, error: "This ip address doesn't exist"});
            }
            await ApiKeyModel.deleteOne({ _id: id });
            return res.json({ success: true });
        } catch (err) {
            console.log("Key delete error ===> ", err);
            return res.status(500).json({ success: false, error: "An error occurred while removing new apikey." });
        }
    }
)

export default ApiKeyRouter;