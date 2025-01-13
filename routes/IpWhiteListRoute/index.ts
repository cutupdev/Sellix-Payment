import { Request, Response, Router } from "express";
import { check, validationResult } from "express-validator";
import IpWhiteListModel from "../../model/IpWhiteListModel";
import SubscriptionModel from "../../model/SubscriptionModel";
import isValidIP from "../../utils/validIpAddress";
import { authMiddleware } from "../../middleware";
import { sleep } from "../../utils/sleep";
import mongoose from "mongoose";

// Create a new instance of the Express Router
const IPWhiteListRouter = Router();

// @route    Post api/ipWhiteList/create
// @desc     Add new white ip address
// @access   Private
IPWhiteListRouter.post(
    '/create',
    check("subscriptionId", "SubscriptionId is required").notEmpty(),
    check("ipAddress", "ipAddress is required").notEmpty(),
    authMiddleware,
    async (req: Request, res: Response) => {
        const subscriptionId = req.body.subscriptionId;
        const ipAddress = req.body.ipAddress;

        // Check valid IP address
        const isIp = isValidIP(ipAddress);
        if (!isIp) {
            return res.status(400).send({ success: false, error: "invalid IP address" })
        }

        try {
            const subscriptionData = await SubscriptionModel.aggregate([
                {
                    $match: { _id: new mongoose.Types.ObjectId(subscriptionId) }
                },
                {
                    $lookup: {
                        from: 'services',
                        localField: 'serviceId',
                        foreignField: '_id',
                        as: 'service'
                    }
                },
                {
                    $project: {
                        serviceName: '$service.serviceName',
                    }
                }
            ])

            if (subscriptionData.length === 0) {
                return res.status(400).json({ success: false, error: 'No subscription data found' })
            }

            if (subscriptionData[0]?.serviceName[0] !== 'grpc') {
                return res.status(400).json({ success: false, error: 'Grpc only can have IP whitelist' });
            }

            if (subscriptionData.length === 0) {
                return res.status(400).json({ success: false, error: "Subscription doesn't exist" });
            }

            const ipLists = await IpWhiteListModel.find({ subscriptionId: subscriptionId });
            for (let i = 0; i < ipLists.length; i++) {
                if (ipLists[i].ip === ipAddress) {
                    return res.status(400).json({ success: false, error: "Same IP address exists" });
                }
            }

            const newIpdata = new IpWhiteListModel({
                subscriptionId: subscriptionId,
                ip: ipAddress
            });

            await newIpdata.save();
            const savedData = await IpWhiteListModel.findOne({ subscriptionId: subscriptionId, ip: ipAddress });
            return res.json({ success: true, data: savedData });
        } catch (err) {
            return res.status(500).json({ success: false })
        }
    }
)

// @route    Post api/ipWhiteList/update
// @desc     Update white ip address
// @access   Private
IPWhiteListRouter.post(
    '/update',
    check("subscriptionId", "SubscriptionId is required").notEmpty(),
    check("ipId", "IpId is required").notEmpty(),
    check("ipAddress", "ipAddress is required").notEmpty(),
    authMiddleware,
    async (req: Request, res: Response) => {
        const ipId = req.body.ipId;
        const ipAddress = req.body.ipAddress;
        const subscriptionId = req.body.subscriptionId;

        // Check valid IP address 
        const isIp = isValidIP(ipAddress);
        if (!isIp) {
            return res.status(400).send({ success: false, error: "invalid Ip address" })
        }

        try {
            const subscriptionData = await SubscriptionModel.aggregate([
                {
                    $match: { _id: new mongoose.Types.ObjectId(subscriptionId) }
                },
                {
                    $lookup: {
                        from: 'services',
                        localField: 'serviceId',
                        foreignField: '_id',
                        as: 'service'
                    }
                },
                {
                    $project: {
                        serviceName: '$service.serviceName',
                    }
                }
            ]);

            if (subscriptionData.length === 0) {
                return res.status(400).json({ success: false, error: "Subscription doesn't exist" });
            }

            if (subscriptionData[0].serviceName[0] !== 'grpc') {
                return res.status(400).json({ success: false, error: 'Grpc only can have IP whitelist' });
            }            

            const newIp = await IpWhiteListModel.findByIdAndUpdate(
                ipId,
                { ip: ipAddress },
                { new: true }
            );

            if (!newIp) {
                return res.status(500).json({ success: false });
            }

            return res.json({ success: true, data: newIp });
        } catch (err) {
            console.log('error updating white ip address ===> ', err);
            return res.status(500).json({ success: false });
        }
    }
)

// @route    Post api/ipWhiteList/delete
// @desc     Delete white ip address
// @access   Private
IPWhiteListRouter.delete(
    '/delete/:id',
    authMiddleware,
    async (req: Request, res: Response) => {
        const id = req.params.id;
        try {
            const data = await IpWhiteListModel.findById(id);
            if (!data) {
                return res.status(400).json({ success: false, error: "This ip address doesn't exist"});
            }
            await IpWhiteListModel.deleteOne({ _id: id });
            return res.json({ success: true });
        } catch (err) {
            console.log('error deleting white ip data ===> ', err);
            return res.status(500).json({ success: false });
        }
    }
)

export default IPWhiteListRouter;